import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export enum UserRole {
  User = 'User',
  Admin = 'Admin',
}

export type UserDocument = User & Document;

@Schema({ timestamps: true })
export class User {
  @Prop({ required: true })
  userName: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ type: String, enum: UserRole, default: UserRole.User })
  role: UserRole;

  @Prop()
  mfaSecret: string;

  @Prop({ default: true })
  verified: boolean;

  @Prop()
  verificationCode: string;

  @Prop({ default: Date.now })
  verificationCodeExpires: Date;

  @Prop({ default: true })
  mfaEnabled: boolean;

  @Prop()
  mfaSecretExpires: Date;

  @Prop({ default: true })
  mfaVerified: boolean;
}

export const UserSchema = SchemaFactory.createForClass(User);
