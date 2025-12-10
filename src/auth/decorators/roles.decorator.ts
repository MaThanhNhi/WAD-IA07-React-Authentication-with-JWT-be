import { SetMetadata } from '@nestjs/common';
import { Role } from '../../user/dto/user-response.dto';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
