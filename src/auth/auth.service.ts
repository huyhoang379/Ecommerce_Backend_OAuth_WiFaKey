// src/auth/auth.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';

interface UserInfo {
  idpUserId: string;
  email: string;
  name?: string;
  picture?: string;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private configService: ConfigService,
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) { }

  /**
   * Sync user info từ IdP vào database
   * KHÔNG lưu token
   */
  async syncUserInfo(userData: UserInfo): Promise<User> {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    let user = await this.userRepository.findOne({
      where: { idpUserId: userData.idpUserId },
    });

    if (!user) {
      this.logger.log(`Creating new user: ${userData.email}`);
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
      user = this.userRepository.create({
        idpUserId: userData.idpUserId,
        email: userData.email,
        name: userData.name,
        picture: userData.picture,
        lastLoginAt: new Date(),
      });
    } else {
      this.logger.log(`Updating existing user: ${userData.email}`);
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      user.email = userData.email;
      if (typeof userData.name !== 'undefined') {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        user.name = userData.name;
      }
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      user.lastLoginAt = new Date();
    }

    // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    return await this.userRepository.save(user);
  }

  /**
   * Lấy user info từ database
   */
  async getUserByIdpUserId(idpUserId: string): Promise<User | null> {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    return await this.userRepository.findOne({
      where: { idpUserId },
    });
  }

  /**
   * Lấy user info bằng email
   */
  async getUserByEmail(email: string): Promise<User | null> {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    return await this.userRepository.findOne({
      where: { email },
    });
  }

  /**
   * Update user preferences
   */
  async updateUserPreferences(
    idpUserId: string,
    preferences: Record<string, any>,
  ): Promise<User> {
    const user = await this.getUserByIdpUserId(idpUserId);
    if (!user) {
      throw new Error('User not found');
    }

    user.preferences = { ...user.preferences, ...preferences };
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    return await this.userRepository.save(user);
  }

  /**
   * Log logout event
   */
  async logLogout(idpUserId: string): Promise<void> {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    await this.userRepository.update(
      { idpUserId },
      { lastLogoutAt: new Date() },
    );
  }

  /**
   * Proxy refresh token request to IdP
   */
  async refreshTokenFromIdp(refreshToken: string) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const oauthConfig = this.configService.get('oauth');

    try {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
      const response = await fetch(oauthConfig.tokenURL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          client_id: oauthConfig.clientId,
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          client_secret: oauthConfig.clientSecret,
        }),
      });

      if (!response.ok) {
        const error = await response.text();
        this.logger.error(`Failed to refresh token: ${error}`);
        throw new Error('Failed to refresh token from IdP');
      }

      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const data = await response.json();

      return {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        access_token: data.access_token,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        refresh_token: data.refresh_token || refreshToken,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        expires_in: data.expires_in,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        token_type: data.token_type || 'Bearer',
      };
    } catch (error) {
      this.logger.error('Refresh token error:', error);
      throw error;
    }
  }

  async exchangeCodeForTokens(code: string) {
    const oauthConfig = this.configService.get('oauth');

    this.logger.log('Calling IdP token endpoint...');

    const response = await fetch(oauthConfig.tokenURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        client_id: oauthConfig.clientId,
        client_secret: oauthConfig.clientSecret, // ✅ Secure in backend
        redirect_uri: oauthConfig.callbackURL,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      this.logger.error(`IdP token error: ${error}`);
      throw new Error('Failed to exchange code for tokens');
    }

    const data = await response.json();
    this.logger.log('Successfully got tokens from IdP');

    return {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_in: data.expires_in || 3600,
      token_type: data.token_type || 'Bearer',
    };
  }

  async fetchUserProfile(accessToken: string) {
    const userInfoUrl = this.configService.get('oauth.userInfoURL');

    this.logger.log('Fetching user profile from IdP...');

    const response = await fetch(userInfoUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error('Failed to fetch user profile');
    }

    return await response.json();
  }
}