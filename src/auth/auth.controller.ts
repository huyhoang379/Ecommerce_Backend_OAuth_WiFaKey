// src/auth/auth.controller.ts
import {
  Controller,
  Get,
  Post,
  Req,
  Res,
  UseGuards,
  Body,
  HttpStatus,
  HttpCode,
  Logger,
  BadRequestException,
  HttpException,
  InternalServerErrorException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { type Response, type Request } from 'express';
import { AuthService } from './auth.service';
import { AuthenticatedUser } from './strategies/oauth.strategy';
import { IdpErrorException } from 'src/common/exceptions/idp-error.exception';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private authService: AuthService,
    private configService: ConfigService,
  ) {}

  /**
   * Bước 1: Redirect to IdP login page
   * Frontend: window.location.href = 'http://localhost:3000/auth/login'
   */
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() body: { code: string; state: string; code_verifier: string },
  ) {
    if (!body.code) {
      throw new BadRequestException('Authorization code is required');
    }

    try {
      this.logger.log(`Exchanging code for tokens: ${body.code}`);

      const tokens = await this.authService.exchangeCodeForTokens(
        body.code,
        body.state,
        body.code_verifier,
      );

      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const profile = await this.authService.fetchUserProfile(
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
        tokens.access_token,
      );

      // Handle ApiResponse wrapper từ IdP
      const userData = profile.data || profile;

      const user = await this.authService.syncUserInfo({
        idpUserId: userData.user_id || userData.userId,
        name: userData.name,
        picture: userData.picture || userData.avatar,
      });

      // eslint-disable-next-line @typescript-eslint/no-base-to-string, @typescript-eslint/restrict-template-expressions
      this.logger.log(`Tokens exchanged ${tokens}`);

      return {
        success: true,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        accessToken: tokens.id_token, // SỬ DỤNG id_token LÀM access_token CHO FRONTEND VÌ JWT STRATEGY CẦN JWT
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        refreshToken: tokens.refresh_token,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        tokenType: tokens.token_type || 'Bearer',
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        expiresIn: tokens.expires_in,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        idToken: tokens.id_token,
        userInfo: {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          userId: userData.user_id,
          localUserId: user.id,
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          email: userData.email,
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          name: userData.name,
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          username: userData.sub || userData.name,
          // IdP trả về "avatar", frontend dùng "picture"
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          picture: userData.avatar || userData.picture,
        },
      };
    } catch (error) {
      // Log error nhưng KHÔNG throw lại với message khác
      this.logger.error('Failed to exchange code:', error);

      // Re-throw IdP errors AS-IS
      if (error instanceof IdpErrorException) {
        throw error;
      }

      // Only wrap unknown errors
      if (error instanceof HttpException) {
        throw error;
      }

      throw new InternalServerErrorException(
        'An unexpected error occurred during authentication',
      );
    }
  }

  /**
   * Bước 2: OAuth callback - IdP redirects here after login
   * URL: http://localhost:3000/auth/callback?code=xxx
   */
  @Get('callback')
  @UseGuards(AuthGuard('oauth2'))
  async callback(@Req() req: Request, @Res() res: Response) {
    const user = req.user as AuthenticatedUser;

    try {
      this.logger.log(`OAuth callback for user: ${user.email}`);

      // Sync user info vào database (KHÔNG lưu token)
      await this.authService.syncUserInfo({
        idpUserId: user.idpUserId,
        email: user.email,
        name: user.name,
        picture: user.picture,
      });

      // Redirect về frontend với tokens
      const frontendUrl = this.configService.get<string>('frontend_url');
      const redirectUrl =
        `${frontendUrl}/auth/callback?` +
        `access_token=${encodeURIComponent(user.idpAccessToken)}&` +
        `refresh_token=${encodeURIComponent(user.idpRefreshToken || '')}&` +
        `token_type=Bearer`;

      this.logger.log('Redirecting to frontend with tokens');
      return res.redirect(redirectUrl);
    } catch (error) {
      this.logger.error('Callback error:', error);
      const frontendUrl = this.configService.get<string>('frontend_url');
      return res.redirect(
        `${frontendUrl}/auth/callback?error=authentication_failed`,
      );
    }
  }

  /**
   * Get current user profile
   * Protected by JWT - verify IdP token
   */
  @Get('profile')
  // @UseGuards(AuthGuard('jwt'))
  async getProfile(@Req() req: Request) {
    const jwtUser = req.user as { userId: string; email: string; name: string };

    // Optional: Lấy thêm info từ database
    const userInfo = await this.authService.getUserByIdpUserId(jwtUser.userId);

    return {
      success: true,
      data: {
        userId: jwtUser.userId,
        email: jwtUser.email,
        name: jwtUser.name,
        preferences: userInfo?.preferences,
        lastLoginAt: userInfo?.lastLoginAt,
      },
    };
  }

  /**
   * Refresh access token
   * Proxy request to IdP
   */
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(@Body() body: { refresh_token: string }) {
    if (!body.refresh_token) {
      throw new BadRequestException('Refresh token is required');
    }

    try {
      this.logger.log('Refreshing access token...');

      const tokens = await this.authService.refreshTokenFromIdp(
        body.refresh_token,
      );

      this.logger.log('✅ Token refresh successful');

      return {
        success: true,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        accessToken: tokens.id_token || tokens.access_token, // SỬ DỤNG id_token LÀM access_token
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        refreshToken: tokens.refresh_token,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        tokenType: tokens.token_type || 'Bearer',
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        expiresIn: tokens.expires_in,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        idToken: tokens.id_token,
      };
    } catch (error) {
      this.logger.error('❌ Failed to refresh token:', error);

      // Re-throw IdP errors AS-IS
      if (error instanceof IdpErrorException) {
        throw error;
      }

      // Only wrap unknown errors
      if (error instanceof HttpException) {
        throw error;
      }

      throw new InternalServerErrorException(
        'An unexpected error occurred during token refresh',
      );
    }
  }

  @Post('revoke')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async revokeRefresh(@Body() body: { refresh_token: string }) {
    if (!body.refresh_token) {
      throw new BadRequestException('Refresh token is required');
    }

    try {
      this.logger.log('Revoking refresh token...');

      const response = await this.authService.requestRevokeRefreshTokenToIdp(
        body.refresh_token,
      );

      this.logger.log('✅ Token refresh successful');

      return {
        success: true,
        status: response.status,
        message: response.message,
      };
    } catch (error) {
      this.logger.error('❌ Failed to revoke refresh token:', error);

      // Re-throw IdP errors AS-IS
      if (error instanceof IdpErrorException) {
        throw error;
      }

      // Only wrap unknown errors
      if (error instanceof HttpException) {
        throw error;
      }

      throw new InternalServerErrorException(
        'An unexpected error occurred during revoke refresh',
      );
    }
  }

  /**
   * Logout
   * Log event và redirect to IdP logout (optional)
   */
  @Post('logout')
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  async logout(@Req() req: Request) {
    const jwtUser = req.user as { userId: string };

    // Log logout event
    await this.authService.logLogout(jwtUser.userId);

    // Return IdP logout URL cho frontend redirect
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const oauthConfig = this.configService.get('oauth');
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
    const logoutUrl = oauthConfig.logoutURL;

    if (logoutUrl) {
      const fullLogoutUrl =
        `${logoutUrl}?` +
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        `client_id=${oauthConfig.clientId}&` +
        `post_logout_redirect_uri=${this.configService.get('frontend_url')}/login`;

      return {
        success: true,
        message: 'Logged out successfully',
        idpLogoutUrl: fullLogoutUrl,
      };
    }

    return {
      success: true,
      message: 'Logged out successfully',
    };
  }

  /**
   * Health check endpoint
   */
  @Get('health')
  health() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
    };
  }
}
