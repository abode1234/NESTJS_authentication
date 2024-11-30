// src/mfa/mfa.module.ts
import { Module } from '@nestjs/common';
import { MfaController } from './mfa.controller';
import { MfaService } from './mfa.service';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from '../users/schemas/user.schema';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
  ],
  controllers: [MfaController],
  providers: [MfaService],
  exports: [MfaService],  // If other modules need to use MfaService
})
export class MfaModule {}

