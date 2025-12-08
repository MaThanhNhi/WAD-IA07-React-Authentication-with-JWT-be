import {
  Injectable,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import bcrypt from 'bcrypt';
import { CreateUserDto } from './dto/create-user.dto';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async register(createUserDto: CreateUserDto) {
    const { email, password } = createUserDto;

    if (!email || !password) {
      throw new BadRequestException('Email and password are required');
    }

    const emailRegex = /^([a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})*$/;
    if (!emailRegex.test(email)) {
      throw new BadRequestException('Invalid email format');
    }

    const passwordRegex =
      /(?=(.*[0-9]))(?=.*[!@#$%^&*()\\[\]{}\-_+=~`|:;"'<>,./?])(?=.*[a-z])(?=(.*[A-Z]))(?=(.*)).{8,}/;
    if (!passwordRegex.test(password)) {
      throw new BadRequestException(
        'Password must be at least 8 characters long and contain a mix of uppercase, lowercase, numeric characters, and special characters',
      );
    }

    // Check if email already exists
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new ConflictException('Email already in use');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
      select: {
        id: true,
        email: true,
        createdAt: true,
      },
    });

    return {
      message: 'User registered successfully',
      user,
    };
  }
}
