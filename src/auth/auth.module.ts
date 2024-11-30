import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { LocalUserStrategy } from './strategies/local-user.strategy';
import { LocalAdminStrategy } from './strategies/local-admin.strategy';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from '../users/schemas/user.schema';
import { AuthController } from "./auth.controller";

@Module({
    imports: [
        MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
        JwtModule.registerAsync({
            imports: [ConfigModule],
            useFactory: async (configService: ConfigService) => ({
                publicKey: configService.get<string>('JWT_SECRET_USER'),
                signOptions: { expiresIn: '1h' },
            }),
            inject: [ConfigService],
        }),
        ConfigModule,
    ],
    providers: [AuthService, LocalUserStrategy, LocalAdminStrategy],
    exports: [AuthService],
    controllers: [AuthController],
})
export class AuthModule {}
