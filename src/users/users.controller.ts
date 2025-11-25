// src/users/users.controller.ts
import { Controller, Get, Put, Body, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { AuthService } from '../auth/auth.service';

@Controller('users')
@UseGuards(JwtAuthGuard)
export class UsersController {
  constructor(private authService: AuthService) {}

  /**
   * Get current user info
   */
  @Get('me')
  async getCurrentUser(@CurrentUser() user: any) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
    const userInfo = await this.authService.getUserByIdpUserId(user.userId);

    return {
      success: true,
      data: {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        userId: user.userId,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        email: user.email,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        name: user.name,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        roles: user.roles,
        preferences: userInfo?.preferences,
        createdAt: userInfo?.createdAt,
        lastLoginAt: userInfo?.lastLoginAt,
      },
    };
  }

  /**
   * Update user preferences
   */
  @Put('me/preferences')
  async updatePreferences(
    @CurrentUser('userId') userId: string,
    @Body() preferences: Record<string, any>,
  ) {
    const updatedUser = await this.authService.updateUserPreferences(
      userId,
      preferences,
    );

    return {
      success: true,
      data: {
        preferences: updatedUser.preferences,
      },
    };
  }
}
