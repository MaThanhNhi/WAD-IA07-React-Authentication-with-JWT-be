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
import { CurrentUser } from './decorators/current-user.decorator';
import { setRefreshCookie, parseExpirationToMs } from './utils/tokens';
import { ConfigService } from '@nestjs/config';

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

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() body: { email: string; password: string }) {
    return this.authService.register(body.email, body.password);
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

    const result = await this.authService.refreshAccessToken(refreshToken);

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
}
