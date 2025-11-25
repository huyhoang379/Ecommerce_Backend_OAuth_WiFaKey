// src/auth/strategies/oauth.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-oauth2';
import { ConfigService } from '@nestjs/config';

interface IdpUserProfile {
  sub: string;
  email: string;
  name?: string;
  preferred_username?: string;
  picture?: string;
}

export interface AuthenticatedUser {
  idpUserId: string;
  email: string;
  name?: string;
  picture?: string;
  idpAccessToken: string;
  idpRefreshToken?: string;
}

@Injectable()
export class OAuthStrategy extends PassportStrategy(Strategy, 'oauth2') {
  constructor(private configService: ConfigService) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    const oauthConfig = configService.get('oauth');

    if (
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      !oauthConfig.authorizationURL ||
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      !oauthConfig.tokenURL ||
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      !oauthConfig.clientId ||
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      !oauthConfig.clientSecret ||
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      !oauthConfig.callbackURL
    ) {
      throw new Error('Missing required OAuth2 configuration');
    }

    super({
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
      authorizationURL: oauthConfig.authorizationURL,
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
      tokenURL: oauthConfig.tokenURL,
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
      clientID: oauthConfig.clientId,
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
      clientSecret: oauthConfig.clientSecret,
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
      callbackURL: oauthConfig.callbackURL,
      scope: ['openid', 'profile', 'email'],
    });
  }

  /**
   * Fetch user profile từ IdP
   */
  // eslint-disable-next-line @typescript-eslint/no-misused-promises
  async userProfile(
    accessToken: string,
    done: (err: Error | null, profile?: any) => void,
  ): Promise<void> {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    const userInfoUrl = this.configService.get('oauth.userInfoURL');

    if (!userInfoUrl) {
      done(new Error('Missing OAUTH_USERINFO_URL configuration'));
      return;
    }

    try {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      const response = await fetch(userInfoUrl, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch user info');
      }

      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const profile: IdpUserProfile = await response.json();

      done(null, {
        id: profile.sub,
        email: profile.email,
        name: profile.name || profile.preferred_username,
        picture: profile.picture,
      });
    } catch (err) {
      done(err as Error);
    }
  }

  /**
   * Validate method - được gọi sau userProfile
   * Chuẩn bị data để trả về controller
   */
  validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: (err: Error | null, user?: AuthenticatedUser) => void,
  ): void {
    const user: AuthenticatedUser = {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
      idpUserId: profile.id,
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
      email: profile.email,
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
      name: profile.name,
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
      picture: profile.picture,
      idpAccessToken: accessToken,
      idpRefreshToken: refreshToken,
    };

    done(null, user);
  }
}
