import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../user.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class ValidateGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private userService: UserService,
    private configService: ConfigService,
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const auth_cookie = context.switchToHttp().getRequest().cookies[
      'auth-cookie'
    ];
    try {
      this.jwtService.verify(auth_cookie.token);
      return true;
    } catch (err) {
      const newAccessToken = await this.userService._regenerateAccessToken(
        auth_cookie.refreshToken,
      );
      if (!newAccessToken) {
        return false;
      }
      const secretData = {
        token: newAccessToken,
        refreshToken: auth_cookie.refreshToken,
      };
      const res = context.switchToHttp().getResponse();
      res.cookie('auth-cookie', secretData, { httpOnly: true });
      return true;
    }
  }
}
