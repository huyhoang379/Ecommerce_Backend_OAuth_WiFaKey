// src/auth/auth.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { IdpErrorException } from 'src/common/exceptions/idp-error.exception';

interface UserInfo {
  idpUserId: string;
  email?: string;
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
  ) {}

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
      // user.email = userData.email;
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
   * Request revoke refresh token to IdP
   * KHÔNG cần access token, chỉ cần client credentials
   */
  async requestRevokeRefreshTokenToIdp(refreshToken: string) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const oauthConfig = this.configService.get('oauth');

    this.logger.log('Calling IdP revoke endpoint...');

    try {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
      const response = await fetch(oauthConfig.revokeRefreshURL, {
        method: 'POST',
        headers: {
          // ❌ BỎ Authorization header
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          token: refreshToken,
          token_type_hint: 'refresh_token',
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          client_id: oauthConfig.clientId,
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          client_secret: oauthConfig.clientSecret,
        }),
      });

      if (!response.ok) {
        let errorData;
        const contentType = response.headers.get('content-type');

        if (contentType?.includes('application/json')) {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          errorData = await response.json();
        } else {
          const errorText = await response.text();
          errorData = {
            error: 'unknown_error',
            error_description: errorText,
          };
        }

        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        const errorCode = errorData.error || 'revoke_refresh_failed';
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        const errorDescription =
          // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
          errorData.error_description || 'Failed to revoke refresh token';

        this.logger.error(
          `IdP revoke refresh error [${response.status}]: ${errorCode} - ${errorDescription}`,
        );

        throw new IdpErrorException(
          errorCode,
          errorDescription,
          response.status,
        );
      }

      // Response có thể là empty body (theo OAuth 2.0 spec)
      let data = {};
      const contentType = response.headers.get('content-type');

      if (contentType?.includes('application/json')) {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unused-vars
        data = await response.json();
      }

      this.logger.log('Successfully revoked refresh token from IdP');

      return {
        status: true,
        message: 'Revoke refresh token thành công!',
      };
    } catch (error) {
      if (error instanceof IdpErrorException) {
        throw error;
      }

      this.logger.error('Network error revoking refresh token:', error);
      throw new IdpErrorException(
        'network_error',
        'Unable to connect to authentication provider',
        503,
      );
    }
  }

  /**
   * Proxy refresh token request to IdP
   */
  async refreshTokenFromIdp(refreshToken: string) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const oauthConfig = this.configService.get('oauth');

    this.logger.log('Calling IdP token endpoint for refresh...');

    try {
      const refreshUrl = oauthConfig.tokenURL.replace('/token', '/refresh');
      const response = await fetch(refreshUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_code',  // IdP dùng tên tùy chỉnh "refresh_code"
          refresh_code: refreshToken,

          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          client_id: oauthConfig.clientId,
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          client_secret: oauthConfig.clientSecret,
        }),
      });

      if (!response.ok) {
        // Parse error response from IdP
        let errorData;
        const contentType = response.headers.get('content-type');

        if (contentType?.includes('application/json')) {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          errorData = await response.json();
        } else {
          const errorText = await response.text();
          errorData = { error: 'unknown_error', error_description: errorText };
        }

        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        const errorCode = errorData.error || 'refresh_failed';
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        const errorDescription =
          // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
          errorData.error_description || 'Failed to refresh access token';

        this.logger.error(
          `IdP refresh error [${response.status}]: ${errorCode} - ${errorDescription}`,
        );

        // Throw custom exception với thông tin từ IdP
        throw new IdpErrorException(
          errorCode,
          errorDescription,
          response.status,
        );
      }

      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const json = await response.json();
      // IdP trả về ApiResponse wrapper: { success, message, data: { accessToken, refreshToken, ... } }
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
      const tokenData = json?.data ?? json;
      this.logger.log('Successfully refreshed tokens from IdP');

      return {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        access_token: tokenData.access_token ?? tokenData.accessToken,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        refresh_token: tokenData.refresh_token ?? tokenData.refreshToken ?? refreshToken,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        expires_in: tokenData.expires_in ?? tokenData.expiresIn ?? 3600,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        token_type: tokenData.token_type ?? tokenData.tokenType ?? 'Bearer',
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        id_token: tokenData.id_token ?? tokenData.idToken,
      };
    } catch (error) {
      // Re-throw IdP errors
      if (error instanceof IdpErrorException) {
        throw error;
      }

      // Handle network/fetch errors
      this.logger.error('Network error refreshing token:', error);
      throw new IdpErrorException(
        'network_error',
        'Unable to connect to authentication provider',
        503,
      );
    }
  }

  async exchangeCodeForTokens(
    code: string,
    state: string,
    code_verifier: string,
  ) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const oauthConfig = this.configService.get('oauth');

    this.logger.log('Calling IdP token endpoint...');

    try {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
      const response = await fetch(oauthConfig.tokenURL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code,
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          client_id: oauthConfig.clientId,
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          client_secret: oauthConfig.clientSecret,
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          redirect_uri: oauthConfig.callbackURL,
          state: state,
          code_verifier: code_verifier,
        }),
      });

      if (!response.ok) {
        // Parse error response from IdP
        let errorData;
        const contentType = response.headers.get('content-type');

        if (contentType?.includes('application/json')) {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          errorData = await response.json();
        } else {
          const errorText = await response.text();
          errorData = { error: 'unknown_error', error_description: errorText };
        }

        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        const errorCode = errorData.error || errorData.errors || 'token_exchange_failed';
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        const errorDescription =
          // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
          errorData.error_description || errorData.message || 'Failed to exchange code for tokens';

        this.logger.error(
          `IdP token error [${response.status}]: ${errorCode} - ${errorDescription}`,
          JSON.stringify(errorData),
        );

        // Throw custom exception với thông tin từ IdP
        throw new IdpErrorException(
          // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
          errorCode,
          // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
          errorDescription,
          response.status,
        );
      }

      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const data = await response.json();
      this.logger.log('Successfully got tokens from IdP');

      // Xử lý wrapper ApiResponse từ IdP
      const tokenData = data.data || data;

      return {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        access_token: tokenData.accessToken || tokenData.access_token,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        refresh_token: tokenData.refreshToken || tokenData.refresh_token,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        expires_in: tokenData.expiresIn || tokenData.expires_in || 3600,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        token_type: tokenData.tokenType || tokenData.token_type || 'Bearer',
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        id_token: tokenData.idToken || tokenData.id_token,
      };
    } catch (error) {
      // Re-throw IdP errors
      if (error instanceof IdpErrorException) {
        throw error;
      }

      // Handle network/fetch errors
      this.logger.error('Network error calling IdP:', error);
      throw new IdpErrorException(
        'network_error',
        'Unable to connect to authentication provider',
        503,
      );
    }
  }

  async fetchUserProfile(accessToken: string) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const oauthConfig = this.configService.get('oauth');

    this.logger.log('Fetching user profile from IdP...');

    try {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
      const response = await fetch(oauthConfig.userInfoURL, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      if (!response.ok) {
        let errorData;
        const contentType = response.headers.get('content-type');

        if (contentType?.includes('application/json')) {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          errorData = await response.json();
        } else {
          const errorText = await response.text();
          errorData = { error: 'unknown_error', error_description: errorText };
        }

        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        const errorCode = errorData.error || errorData.errors || 'userinfo_failed';
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        const errorDescription =
          // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
          errorData.error_description || errorData.message || 'Failed to fetch user profile';

        this.logger.error(
          `IdP userinfo error [${response.status}]: ${errorCode} - ${errorDescription}`,
          JSON.stringify(errorData),
        );

        throw new IdpErrorException(
          // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
          errorCode,
          // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
          errorDescription,
          response.status,
        );
      }

      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const profile = await response.json();
      this.logger.log('Successfully fetched user profile');

      // eslint-disable-next-line @typescript-eslint/no-unsafe-return
      return profile;
    } catch (error) {
      if (error instanceof IdpErrorException) {
        throw error;
      }

      this.logger.error('Network error fetching user profile:', error);
      throw new IdpErrorException(
        'network_error',
        'Unable to fetch user profile from authentication provider',
        503,
      );
    }
  }
}
