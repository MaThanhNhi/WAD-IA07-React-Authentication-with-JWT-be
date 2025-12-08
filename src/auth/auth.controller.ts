import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  Get,
  Delete,
  UseGuards,
  Req,
  Res,
  Param,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { Roles } from './decorators/roles.decorator';
import { CurrentUser } from './decorators/current-user.decorator';

// Role values for RBAC
const Role = {
  USER: 'USER',
  ADMIN: 'ADMIN',
  MODERATOR: 'MODERATOR',
} as const;

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  private extractMetadata(req: Request) {
    return {
      userAgent: req.headers['user-agent'],
      ipAddress: req.ip || req.socket.remoteAddress,
      fingerprint: req.headers['x-fingerprint'] as string | undefined,
    };
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const metadata = this.extractMetadata(req);
    const result = await this.authService.login(loginDto, metadata);

    // Set refresh token in HTTP-only cookie
    res.cookie('refreshToken', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // HTTPS only in production
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
    });

    // Return access token and user info (not the refresh token)
    return {
      accessToken: result.accessToken,
      user: result.user,
    };
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Body('refreshToken') bodyRefreshToken?: string,
  ) {
    // Try to get refresh token from cookie first, then from body
    const refreshToken = req.cookies?.refreshToken || bodyRefreshToken;
    const metadata = this.extractMetadata(req);

    const result = await this.authService.refreshAccessToken(
      refreshToken,
      metadata,
    );

    // Update the refresh token cookie
    res.cookie('refreshToken', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/',
    });

    return {
      accessToken: result.accessToken,
      user: result.user,
    };
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Body('refreshToken') bodyRefreshToken?: string,
  ) {
    const refreshToken = req.cookies?.refreshToken || bodyRefreshToken;
    const result = await this.authService.logout(refreshToken);

    // Clear the refresh token cookie
    res.clearCookie('refreshToken', { path: '/' });

    return result;
  }

  @Post('logout-all')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async logoutAllDevices(
    @CurrentUser() user: any,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.logoutAllDevices(user.id);

    // Clear the refresh token cookie
    res.clearCookie('refreshToken', { path: '/' });

    return result;
  }

  @Get('sessions')
  @UseGuards(JwtAuthGuard)
  async getSessions(@CurrentUser() user: any) {
    return this.authService.getUserSessions(user.id);
  }

  @Delete('sessions/:id')
  @UseGuards(JwtAuthGuard)
  async revokeSession(@Param('id') sessionId: string) {
    return this.authService.revokeToken(sessionId);
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  async getProfile(@CurrentUser() user: any) {
    return user;
  }

  // Example: Admin-only endpoint
  @Get('admin/users')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  async getUsers(@CurrentUser() user: any) {
    return {
      message: 'Admin access granted',
      adminUser: user,
    };
  }

  // Example: Admin or Moderator endpoint
  @Get('moderation/stats')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN, Role.MODERATOR)
  async getModerationStats(@CurrentUser() user: any) {
    return {
      message: 'Moderator/Admin access granted',
      user,
    };
  }
}
