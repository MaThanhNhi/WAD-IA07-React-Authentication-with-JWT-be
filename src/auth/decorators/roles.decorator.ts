import { SetMetadata } from '@nestjs/common';

// Define Role type locally to avoid Prisma client import issues
type Role = 'USER' | 'ADMIN' | 'MODERATOR';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
