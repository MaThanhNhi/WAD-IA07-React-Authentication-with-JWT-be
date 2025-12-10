import { IsEmail, IsString } from 'class-validator';

export type Role = 'USER' | 'ADMIN' | 'MODERATOR';

export class UserResponseDto {
  @IsString()
  id: string;

  @IsEmail()
  email: string;

  @IsString()
  role: Role;

  @IsString()
  createdAt: Date;
}
