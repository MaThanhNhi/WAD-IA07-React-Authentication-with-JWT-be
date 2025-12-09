import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  Get,
  UseGuards,
  Req,
  Res,
  Delete,
  Param,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { Roles } from './decorators/roles.decorator';
import { CurrentUser } from './decorators/current-user.decorator';
import { setRefreshCookie, parseExpirationToMs } from './utils/tokens';
import { ConfigService } from '@nestjs/config';

const Role = {
  USER: 'USER',
  ADMIN: 'ADMIN',
  MODERATOR: 'MODERATOR',
} as const;

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

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

    const refreshExpStr = this.configService.get<string>(
      'JWT_REFRESH_EXPIRATION',
      '7d',
    );
    const refreshExpMs = parseExpirationToMs(refreshExpStr);
    setRefreshCookie(res, result.refreshToken, refreshExpMs);

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
  ) {
    const refreshToken = req.cookies?.refreshToken as string;
    const metadata = this.extractMetadata(req);

    const result = await this.authService.refreshAccessToken(
      refreshToken,
      metadata,
    );

    const refreshExpStr = this.configService.get<string>(
      'JWT_REFRESH_EXPIRATION',
      '7d',
    );
    const refreshExpMs = parseExpirationToMs(refreshExpStr);
    setRefreshCookie(res, result.refreshToken, refreshExpMs);

    return {
      accessToken: result.accessToken,
      user: result.user,
    };
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies?.refreshToken as string;
    const result = await this.authService.logout(refreshToken);

    res.clearCookie('refreshToken', { path: '/' });

    return result;
  }

  @Post('logout-all')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async logoutAllDevices(
    @CurrentUser() user: { id: string; email: string; role: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.logoutAllDevices(user.id);

    res.clearCookie('refreshToken', { path: '/' });

    return result;
  }

  @Get('sessions')
  @UseGuards(JwtAuthGuard)
  async getSessions(
    @CurrentUser() user: { id: string; email: string; role: string },
  ) {
    return this.authService.getUserSessions(user.id);
  }

  @Delete('sessions/:id')
  @UseGuards(JwtAuthGuard)
  async revokeSession(@Param('id') sessionId: string) {
    return this.authService.revokeToken(sessionId);
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  getProfile(@CurrentUser() user: { id: string; email: string; role: string }) {
    return user;
  }

  // Example: Admin-only endpoint
  @Get('admin/users')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  getUsers(@CurrentUser() user: { id: string; email: string; role: string }) {
    return {
      message: 'Admin access granted',
      adminUser: user,
    };
  }

  // Example: Admin or Moderator endpoint
  @Get('moderation/stats')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN, Role.MODERATOR)
  getModerationStats(
    @CurrentUser() user: { id: string; email: string; role: string },
  ) {
    return {
      message: 'Moderator/Admin access granted',
      user,
    };
  }
}
