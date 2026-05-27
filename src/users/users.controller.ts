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
    try {
      this.logger.log(`Getting user info for idpUserId: ${user.idpUserId}`);

      const userInfo = await this.authService.getUserByIdpUserId(
        user.idpUserId,
      );

      this.logger.log(`Query result: ${userInfo ? 'FOUND' : 'NOT FOUND'}`);

      if (userInfo) {
        this.logger.log(`User data: ${JSON.stringify(userInfo)}`);
      }

      if (!userInfo) {
        throw new NotFoundException('User not found');
      }

      const response = {
        success: true,
        data: {
          id: userInfo.id,
          idpUserId: userInfo.idpUserId,
          email: userInfo.email,
        },
      };

      this.logger.log(`Sending response: ${JSON.stringify(response)}`);
      return response;
    } catch (error) {
      this.logger.error(
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        `Error in getCurrentUser: ${error.message}`,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        error.stack,
      );
      throw error;
    }
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
