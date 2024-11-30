import { Controller, Post, Req, UseGuards, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @UseGuards(AuthGuard('local-user'))
    @Post('login-user')
    async loginUser(@Req() req) {
        try {
            return await this.authService.loginUser(req.user);
        } catch (error) {
            if (error instanceof UnauthorizedException && error.message === 'OTP verification required') {
                return { message: 'OTP verification required', requireOtp: true, userId: req.user.email };
            }
            throw error;
        }
    }

    @UseGuards(AuthGuard('local-admin'))
    @Post('login-admin')
    async loginAdmin(@Req() req) {
        try {
            return await this.authService.loginAdmin(req.user);
        } catch (error) {
            if (error instanceof UnauthorizedException && error.message === 'OTP verification required') {
                return { message: 'OTP verification required', requireOtp: true, userId: req.user.email };
            }
            throw error;
        }
    }
}
