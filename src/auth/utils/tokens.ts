import { createHash } from 'crypto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import type { Response } from 'express';

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function setRefreshCookie(
  res: Response,
  refreshToken: string,
  expiresIn: number,
) {
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: expiresIn,
    path: '/',
  });
}

export function calculateExpirationDate(expirationString: string): Date {
  const expiresAt = new Date();

  const match = expirationString.match(/^(\d+)([smhd])$/);

  if (!match) {
    return new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  }

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case 's':
      expiresAt.setSeconds(expiresAt.getSeconds() + value);
      break;
    case 'm':
      expiresAt.setMinutes(expiresAt.getMinutes() + value);
      break;
    case 'h':
      expiresAt.setHours(expiresAt.getHours() + value);
      break;
    case 'd':
      expiresAt.setDate(expiresAt.getDate() + value);
      break;
    default:
      expiresAt.setDate(expiresAt.getDate() + 7);
  }

  return expiresAt;
}

export function parseExpirationToMs(expirationString: string): number {
  const match = expirationString.match(/^(\d+)([smhd])$/);
  if (!match) {
    // Default to 7 days
    return 7 * 24 * 60 * 60 * 1000;
  }
  const value = parseInt(match[1], 10);
  const unit = match[2];
  switch (unit) {
    case 's':
      return value * 1000;
    case 'm':
      return value * 60 * 1000;
    case 'h':
      return value * 60 * 60 * 1000;
    case 'd':
      return value * 24 * 60 * 60 * 1000;
    default:
      return 7 * 24 * 60 * 60 * 1000;
  }
}

/**
 * Generate JWT access and refresh tokens
 * @param jwtService - NestJS JWT service
 * @param configService - NestJS Config service
 * @param userId - User ID to encode in token
 * @param role - User role to encode in access token
 * @returns Object containing accessToken and refreshToken
 */
export function generateTokenPair(
  jwtService: JwtService,
  configService: ConfigService,
  userId: string,
  role: string,
): { accessToken: string; refreshToken: string } {
  const accessPayload = { sub: userId, role };
  const refreshPayload = { sub: userId };

  const accessSecret = configService.get<string>('JWT_ACCESS_SECRET');
  const refreshSecret = configService.get<string>('JWT_REFRESH_SECRET');
  const accessExpiration = configService.get<string>(
    'JWT_ACCESS_EXPIRATION',
    '15m',
  );
  const refreshExpiration = configService.get<string>(
    'JWT_REFRESH_EXPIRATION',
    '7d',
  );

  if (!accessSecret || !refreshSecret) {
    throw new Error('JWT secrets not configured in environment variables');
  }

  const accessToken = jwtService.sign(accessPayload, {
    secret: accessSecret,
    expiresIn: accessExpiration as any,
  });

  const refreshToken = jwtService.sign(refreshPayload, {
    secret: refreshSecret,
    expiresIn: refreshExpiration as any,
  });

  return { accessToken, refreshToken };
}

export interface TokenMetadata {
  userAgent?: string;
  ipAddress?: string;
  fingerprint?: string;
}
