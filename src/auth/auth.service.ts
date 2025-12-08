import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { createHash } from 'crypto';

interface TokenMetadata {
  userAgent?: string;
  ipAddress?: string;
  fingerprint?: string;
}

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}
  async login(loginDto: LoginDto, metadata?: TokenMetadata) {
    const { email, password } = loginDto;    // Find user by email
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

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }    // Generate tokens
    const tokens = await this.generateTokens(user.id, user.role);

    // Store refresh token with metadata in database
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
      // Verify refresh token
      const decoded = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });

      // Hash the refresh token to find it in database
      const hashedToken = this.hashToken(refreshToken);

      // Check if refresh token exists in database and is not expired
      const storedToken = await this.prisma.refreshToken.findUnique({
        where: { hashedToken },
        include: { user: true },
      });

      if (!storedToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Check if token is revoked
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

      // Generate new access token with role
      const payload = { sub: decoded.sub, role: storedToken.user.role };
      const accessToken = this.jwtService.sign(payload, {
        secret: process.env.JWT_ACCESS_SECRET as string,
        expiresIn: (process.env.JWT_ACCESS_EXPIRATION || '15m') as any,
      });

      // Optional: Rotate refresh token (security best practice)
      const newRefreshToken = this.jwtService.sign(
        { sub: decoded.sub },
        {
          secret: process.env.JWT_REFRESH_SECRET as string,
          expiresIn: (process.env.JWT_REFRESH_EXPIRATION || '7d') as any,
        },
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
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }
  async logout(refreshToken: string) {
    if (!refreshToken) {
      return { message: 'Logged out successfully' };
    }

    try {
      // Hash the token before lookup
      const hashedToken = this.hashToken(refreshToken);

      // Delete refresh token from database
      await this.prisma.refreshToken.delete({
        where: { hashedToken },
      });
    } catch (error) {
      // Token doesn't exist, that's fine
    }

    return { message: 'Logged out successfully' };
  }

  async logoutAllDevices(userId: string) {
    // Delete all refresh tokens for this user
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

  async cleanupExpiredTokens() {
    const result = await this.prisma.refreshToken.deleteMany({
      where: {
        OR: [
          { expiresAt: { lt: new Date() } },
          { isRevoked: true },
        ],
      },
    });

    return { deletedCount: result.count };
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
    private async generateTokens(userId: string, role: string) {
    const payload = { sub: userId, role };
    
    const accessToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_ACCESS_SECRET as string,
      expiresIn: (process.env.JWT_ACCESS_EXPIRATION || '15m') as any,
    });

    const refreshToken = this.jwtService.sign({ sub: userId }, {
      secret: process.env.JWT_REFRESH_SECRET as string,
      expiresIn: (process.env.JWT_REFRESH_EXPIRATION || '7d') as any,
    });

    return { accessToken, refreshToken };
  }

  private async storeRefreshToken(
    userId: string,
    token: string,
    metadata?: TokenMetadata,
  ) {
    // Hash the token before storing
    const hashedToken = this.hashToken(token);

    // Calculate expiration date (7 days from now by default)
    const expirationDays = 7;
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + expirationDays);

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

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }
}
