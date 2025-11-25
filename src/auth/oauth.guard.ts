import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class OAuthAuthGuard extends AuthGuard('oauth2-idp') {}
