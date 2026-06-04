// src/auth/strategies/jwt.strategy.ts
import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { passportJwtSecret } from 'jwks-rsa';
import { ConfigService } from '@nestjs/config';

export interface JwtPayload {
  sub: string; // Username (có thể thay đổi)
  user_id: string; // ✅ STABLE ID từ IdP - dùng làm primary identifier
  email?: string;
  name?: string;
  preferred_username?: string;
  iat: number;
  exp: number;
  scope?: string;
  client_id?: string;
  realm_access?: {
    roles: string[];
  };
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  private readonly logger = new Logger(JwtStrategy.name);

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
      // Thêm aud nếu cần
      // audience: oauthConfig.clientId
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
      issuer: oauthConfig.issuer,
      algorithms: ['RS256'],
    });
  }

  /**
   * ✅ Validate JWT payload
   * Token đã được verify bằng public key từ JWKS
   * Không cần query database - stateless authentication
   */
  validate(payload: JwtPayload) {
    // ✅ CRITICAL: Validate user_id (stable identifier)
    // OIDC standard uses 'sub' as the stable identifier, but fallback to 'user_id' if used
    const idpUserId = payload.user_id || payload.sub;
    if (!idpUserId) {
      throw new UnauthorizedException('Invalid token payload: missing user_id and sub');
    }

    // Validate sub (username) - optional warning
    if (!payload.sub) {
      this.logger.warn('Token missing sub (username) claim');
    }

    // Validate token expiration (double check)
    if (payload.exp && Date.now() >= payload.exp * 1000) {
      throw new UnauthorizedException('Token expired');
    }

    // Extract roles
    const roles = payload.realm_access?.roles || [];

    // ✅ CRITICAL FIX: Dùng user_id làm idpUserId (stable identifier)
    return {
      idpUserId: idpUserId, // ✅ Stable ID từ IdP
      username: payload.sub, // ✅ Username (có thể thay đổi)
      email: payload.email,
      name: payload.name || payload.preferred_username,
      roles: roles,
      scope: payload.scope,

      // Optional: Include raw payload for debugging
      _raw: payload,
    };
  }
}
