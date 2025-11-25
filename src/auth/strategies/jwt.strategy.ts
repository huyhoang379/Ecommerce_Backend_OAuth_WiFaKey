// src/auth/strategies/jwt.strategy.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { passportJwtSecret } from 'jwks-rsa';
import { ConfigService } from '@nestjs/config';

export interface JwtPayload {
  sub: string;
  email: string;
  name?: string;
  preferred_username?: string;
  iat: number;
  exp: number;
  scope?: string;
  realm_access?: {
    roles: string[];
  };
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private configService: ConfigService) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const oauthConfig = configService.get('oauth');

    // eslint-disable-next-line @typescript-eslint/no-unsafe-call
    super({
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),

      // CRITICAL: Verify token bằng JWKS từ IdP
      secretOrKeyProvider: passportJwtSecret({
        cache: true, // Cache public keys (NOT tokens)
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        jwksUri: oauthConfig.jwksUri,
      }),

      ignoreExpiration: false,
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
      audience: oauthConfig.clientId,
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
      issuer: oauthConfig.issuer,
      algorithms: ['RS256'],
    });
  }

  /**
   * Validate JWT payload
   * KHÔNG query database
   * Token validity được đảm bảo bởi signature verification
   */
  validate(payload: JwtPayload) {
    if (!payload.sub || !payload.email) {
      throw new UnauthorizedException('Invalid token payload');
    }

    // Extract roles nếu có
    const roles = payload.realm_access?.roles || [];

    // Return data này sẽ được gán vào req.user
    return {
      userId: payload.sub,
      email: payload.email,
      name: payload.name || payload.preferred_username,
      roles: roles,
    };
  }
}
