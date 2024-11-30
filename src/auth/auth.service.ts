import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { User, UserDocument } from '../users/schemas/user.schema';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {

    constructor(
        @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
    ) {}

    async validateUserCredentials(email: string, password: string): Promise<UserDocument | null> {
        const user = await this.userModel.findOne({ email, role: 'User' });
        if (!user) {
            return null;
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        return isPasswordValid ? user : null;
    }

    async validateAdminCredentials(email: string, password: string): Promise<UserDocument | null> {
        const admin = await this.userModel.findOne({ email, role: 'Admin' });
        if (!admin) {
            return null;
        }
        const isPasswordValid = await bcrypt.compare(password, admin.password);
        return isPasswordValid ? admin : null;
    }

    async loginUser(user: UserDocument): Promise<any> {
        if (user.mfaEnabled && !user.mfaVerified) {
            throw new UnauthorizedException('OTP verification required');
        }
        const payload = { email: user.email, sub: user._id, role: user.role };
        const accessToken = this.jwtService.sign(payload, {
            secret: this.configService.get<string>('JWT_SECRET_USER'),
        });
        const { password, ...result } = user.toJSON();
        return { ...result, accessToken };
    }

    async loginAdmin(admin: UserDocument): Promise<any> {
        if (admin.mfaEnabled && !admin.mfaVerified) {
            throw new UnauthorizedException('OTP verification required');
        }
        const payload = { email: admin.email, sub: admin._id, role: admin.role };
        const accessToken = this.jwtService.sign(payload, {
            secret: this.configService.get<string>('JWT_SECRET_ADMIN'),
        });
        const { password, ...result } = admin.toJSON();
        return { ...result, accessToken };
    }



}
