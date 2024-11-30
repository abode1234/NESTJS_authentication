import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import {AuthService} from '../auth.service';

@Injectable()
export class LocalUserStrategy extends PassportStrategy(Strategy, 'local-user') {
  constructor(private authService: AuthService) {
    super({ usernameField: 'email',
      passwordField: 'password',
    });
  }

  async validate(email: string, password: string): Promise<any> {
     console.log(`LocalUserStrategy validating: ${email}`);
    const user = await this.authService.validateUserCredentials(email, password);
    if (!user) {
        console.log(`User validation failed for email: ${email}`);
      throw new UnauthorizedException('Invalid email or password');
    }
    console.log(`User validation successful for email: ${email}`);
    return user;
  }
}
