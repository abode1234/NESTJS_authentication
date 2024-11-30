import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalAdminStrategy extends PassportStrategy(Strategy, 'local-admin') {
    constructor(private readonly authService: AuthService) {
        super({
            usernameField: 'email',
            passwordField: 'password',
        });
    }

    async validate(email: string, password: string): Promise<any> {
        console.log(`LocalAdminStrategy validating: ${email}`);
        const admin = await this.authService.validateAdminCredentials(email, password);
        if (!admin) {
            console.log(`Admin validation failed for email: ${email}`);
            throw new UnauthorizedException('Invalid email or password for admin');
        }
        console.log(`Admin validation successful for email: ${email}`);
        return admin;
    }
}
