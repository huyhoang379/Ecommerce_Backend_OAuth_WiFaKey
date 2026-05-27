// src/auth/guards/jwt-auth.guard.ts
import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger(JwtAuthGuard.name);

  canActivate(context: ExecutionContext) {
    return super.canActivate(context); // chỉ verify token
  }

  handleRequest(err, user, info) {
    console.log('=== GUARD HANDLE REQUEST ===');
    console.log('Error:', err);
    console.log('User:', user);
    console.log('Info:', info);
    console.log('============================');

    if (err || !user) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      console.error('❌ Authentication failed:', info?.message || err?.message);
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      throw err || new UnauthorizedException(info?.message || 'Unauthorized');
    }
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return user;
  }
}
