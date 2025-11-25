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
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import type { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { AuthenticatedUser } from './strategies/oauth.strategy';

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
  async login(@Body() body: { code: string }) {
    if (!body.code) {
      throw new BadRequestException('Authorization code is required');
    }

    try {
      this.logger.log(`Exchanging code for tokens: ${body.code}`);

      // Call IdP to exchange code for tokens
      const tokens = await this.authService.exchangeCodeForTokens(body.code);

      // Fetch user profile
      // const profile = await this.authService.fetchUserProfile(tokens.access_token);

      // Sync user to database
      // await this.authService.syncUserInfo({
      //   idpUserId: profile.sub,
      //   email: profile.email,
      //   name: profile.name,
      // });

      return {
        success: true,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        accessToken: tokens.access_token,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        refreshToken: tokens.refresh_token,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        tokenType: tokens.token_type || 'Bearer',
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        expiresIn: tokens.expires_in,
        // userInfo: {
        //   userId: profile.sub,
        //   email: profile.email,
        //   name: profile.name,
        // },
      };
    } catch (error) {
      this.logger.error('Failed to exchange code:', error);
      throw new UnauthorizedException('Failed to authenticate with IdP');
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
  @UseGuards(AuthGuard('jwt'))
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
      return {
        success: false,
        message: 'Refresh token is required',
      };
    }

    try {
      const tokens = await this.authService.refreshTokenFromIdp(
        body.refresh_token,
      );

      return {
        success: true,
        data: tokens,
      };
    } catch (error) {
      this.logger.error('Refresh token failed:', error);
      return {
        success: false,
        message: 'Failed to refresh token',
      };
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
