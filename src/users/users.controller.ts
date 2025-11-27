// src/users/users.controller.ts
import {
  Controller,
  Get,
  Put,
  Body,
  UseGuards,
  NotFoundException,
  Logger,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { AuthService } from '../auth/auth.service';

interface CurrentUserPayload {
  idpUserId: string; // ✅ user_id từ IdP (stable)
  username: string; // ✅ sub từ IdP (username)
  email?: string;
  name?: string;
  roles?: string[];
}

@Controller('users')
@UseGuards(JwtAuthGuard) // ✅ Verify access token bằng JWKS
export class UsersController {
  private readonly logger = new Logger(UsersController.name);

  constructor(private authService: AuthService) {}

  /**
   * ✅ Get current user info
   * Access token đã được verify bởi JwtAuthGuard
   */
  @Get('me')
  async getCurrentUser(@CurrentUser() user: CurrentUserPayload) {
    this.logger.log(`Getting user info for idpUserId: ${user.idpUserId}`);

    // ✅ Lấy user từ database bằng idpUserId
    const userInfo = await this.authService.getUserByIdpUserId(user.idpUserId);

    // Case 1: User chưa được sync vào database (first login)
    if (!userInfo) {
      this.logger.warn(
        `User ${user.idpUserId} not found in database - need to sync first`,
      );

      // Option A: Auto-sync user info (recommended)
      if (user.email) {
        const syncedUser = await this.authService.syncUserInfo({
          idpUserId: user.idpUserId,
          email: user.email,
          name: user.name,
        });

        this.logger.log(`User ${user.idpUserId} auto-synced to database`);

        return {
          success: true,
          data: {
            id: syncedUser.id,
            idpUserId: syncedUser.idpUserId,
            email: syncedUser.email,
            name: syncedUser.name,
            picture: syncedUser.picture,
            preferences: syncedUser.preferences,
            createdAt: syncedUser.createdAt,
            lastLoginAt: syncedUser.lastLoginAt,
          },
        };
      }

      // Option B: Return error (nếu không muốn auto-sync)
      throw new NotFoundException(
        'User not found in database. Please complete registration.',
      );
    }

    // Case 2: User đã tồn tại trong database
    return {
      success: true,
      data: {
        id: userInfo.id,
        idpUserId: userInfo.idpUserId,
        email: userInfo.email,
        name: userInfo.name,
        picture: userInfo.picture,
        preferences: userInfo.preferences,
        createdAt: userInfo.createdAt,
        lastLoginAt: userInfo.lastLoginAt,
        lastLogoutAt: userInfo.lastLogoutAt,

        // Include info từ token (roles, scope)
        roles: user.roles,
      },
    };
  }

  /**
   * ✅ Update user preferences
   * Access token đã được verify bởi JwtAuthGuard
   */
  @Put('me/preferences')
  async updatePreferences(
    @CurrentUser('idpUserId') idpUserId: string,
    @Body() preferences: Record<string, any>,
  ) {
    this.logger.log(`Updating preferences for user: ${idpUserId}`);

    // Validate user exists
    const user = await this.authService.getUserByIdpUserId(idpUserId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const updatedUser = await this.authService.updateUserPreferences(
      idpUserId,
      preferences,
    );

    return {
      success: true,
      message: 'Preferences updated successfully',
      data: {
        preferences: updatedUser.preferences,
      },
    };
  }

  /**
   * ✅ Get user profile (from token only - no database query)
   * Useful cho stateless operations
   */
  @Get('profile')
  getProfile(@CurrentUser() user: CurrentUserPayload) {
    return {
      success: true,
      data: {
        idpUserId: user.idpUserId, // user_id từ IdP
        username: user.username, // sub từ IdP
        email: user.email,
        name: user.name,
        roles: user.roles,
      },
    };
  }
}
