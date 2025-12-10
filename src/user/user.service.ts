import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { UserResponseDto } from './dto/user-response.dto';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async getProfile(userId: string): Promise<UserResponseDto> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        role: true,
        createdAt: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return user;
  }

  async getAllUsers(adminUserId: string) {
    // Verify admin is making the request (already verified by guard, but good practice)
    const admin = await this.prisma.user.findUnique({
      where: { id: adminUserId },
      select: { role: true },
    });

    if (!admin || admin.role !== 'ADMIN') {
      throw new UnauthorizedException('Admin access required');
    }

    const users = await this.prisma.user.findMany({
      select: {
        id: true,
        email: true,
        role: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    return {
      message: 'Admin access granted',
      users,
      adminUser: { id: adminUserId },
    };
  }

  async getModerationStats(userId: string) {
    // Get user info
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        role: true,
        createdAt: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Get basic stats
    const totalUsers = await this.prisma.user.count();
    const totalSessions = await this.prisma.refreshToken.count({
      where: {
        isRevoked: false,
        expiresAt: { gt: new Date() },
      },
    });

    return {
      message: 'Moderator/Admin access granted',
      user,
      stats: {
        totalUsers,
        activeSessions: totalSessions,
      },
    };
  }
}
