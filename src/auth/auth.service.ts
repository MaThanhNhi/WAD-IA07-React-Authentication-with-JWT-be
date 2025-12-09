import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import {
  hashToken,
  generateTokenPair,
  calculateExpirationDate,
  type TokenMetadata,
} from './utils/tokens';

@Injectable()
export class AuthService {
  private readonly jwtRefreshSecret: string;
  private readonly jwtRefreshExpiration: string;

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {
    this.jwtRefreshSecret =
      this.configService.get<string>('JWT_REFRESH_SECRET')!;
    this.jwtRefreshExpiration = this.configService.get<string>(
      'JWT_REFRESH_EXPIRATION',
      '7d',
    )!;
  }

  async login(loginDto: LoginDto, metadata?: TokenMetadata) {
    const { email, password } = loginDto;

    const user = await this.prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        password: true,
        role: true,
        createdAt: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const tokens = generateTokenPair(
      this.jwtService,
      this.configService,
      user.id,
      user.role,
    );

    await this.storeRefreshToken(user.id, tokens.refreshToken, metadata);

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        createdAt: user.createdAt,
      },
    };
  }

  async refreshAccessToken(refreshToken: string, metadata?: TokenMetadata) {
    if (!refreshToken) {
      throw new BadRequestException('Refresh token is required');
    }

    try {
      const decoded = this.jwtService.verify(refreshToken, {
        secret: this.jwtRefreshSecret,
      });

      const hashedToken = hashToken(refreshToken);

      const storedToken = await this.prisma.refreshToken.findUnique({
        where: { hashedToken },
        include: { user: true },
      });

      if (!storedToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      if (storedToken.isRevoked) {
        // If a revoked token is used, revoke all user's tokens as a security measure
        await this.logoutAllDevices(storedToken.userId);
        throw new UnauthorizedException('Token has been revoked');
      }

      if (storedToken.expiresAt < new Date()) {
        // Token expired, delete it
        await this.prisma.refreshToken.delete({
          where: { id: storedToken.id },
        });
        throw new UnauthorizedException('Refresh token expired');
      }

      // Update lastUsedAt timestamp
      await this.prisma.refreshToken.update({
        where: { id: storedToken.id },
        data: { lastUsedAt: new Date() },
      });

      const { accessToken, refreshToken: newRefreshToken } = generateTokenPair(
        this.jwtService,
        this.configService,
        storedToken.user.id,
        storedToken.user.role,
      );

      // Delete old refresh token and store new one
      await this.prisma.refreshToken.delete({
        where: { id: storedToken.id },
      });
      await this.storeRefreshToken(decoded.sub, newRefreshToken, metadata);

      return {
        accessToken,
        refreshToken: newRefreshToken,
        user: {
          id: storedToken.user.id,
          email: storedToken.user.email,
          role: storedToken.user.role,
        },
      };
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  async logout(refreshToken?: string) {
    if (!refreshToken) {
      return { message: 'Logged out successfully' };
    }

    try {
      const hashedToken = hashToken(refreshToken);

      await this.prisma.refreshToken.delete({
        where: { hashedToken },
      });
    } catch {
      // Token doesn't exist, that's fine
    }

    return { message: 'Logged out successfully' };
  }

  async logoutAllDevices(userId: string) {
    await this.prisma.refreshToken.deleteMany({
      where: { userId },
    });

    return { message: 'Logged out from all devices successfully' };
  }

  async revokeToken(tokenId: string) {
    await this.prisma.refreshToken.update({
      where: { id: tokenId },
      data: { isRevoked: true },
    });

    return { message: 'Token revoked successfully' };
  }

  async getUserSessions(userId: string) {
    const sessions = await this.prisma.refreshToken.findMany({
      where: {
        userId,
        isRevoked: false,
        expiresAt: { gt: new Date() },
      },
      select: {
        id: true,
        createdAt: true,
        lastUsedAt: true,
        expiresAt: true,
        userAgent: true,
        ipAddress: true,
      },
      orderBy: { lastUsedAt: 'desc' },
    });

    return sessions;
  }

  async validateUser(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        createdAt: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return user;
  }

  private async storeRefreshToken(
    userId: string,
    token: string,
    metadata?: TokenMetadata,
  ) {
    const hashedToken = hashToken(token);
    const expiresAt = calculateExpirationDate(this.jwtRefreshExpiration);

    await this.prisma.refreshToken.create({
      data: {
        hashedToken,
        userId,
        expiresAt,
        userAgent: metadata?.userAgent,
        ipAddress: metadata?.ipAddress,
        fingerprint: metadata?.fingerprint,
      },
    });
  }
}
