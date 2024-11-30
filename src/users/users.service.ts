import { Injectable, ConflictException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './schemas/user.schema';
import { RegisterUserDto } from './dto/register-user.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
    constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

    // TODO : create user
    async registerUser(registerUserDto: RegisterUserDto): Promise<User> {
        const { userName, email, password } = registerUserDto;

        const existingUser = await this.userModel.findOne({ email });
        if (existingUser) {
            throw new ConflictException('Email already in use');
        }

        const salt = await bcrypt.genSalt(14);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new this.userModel({
            userName,
            email,
            password: hashedPassword,
            role: 'User',
        });

        return newUser.save();
    }

    // TODO : create admin
    async registerAdmin(registerUserDto: RegisterUserDto): Promise<User> {
        const { userName, email, password } = registerUserDto;

        const existingAdmin = await this.userModel.findOne({ email });
        if (existingAdmin) {
            throw new ConflictException('Email already in use');
        }

        const salt = await bcrypt.genSalt(14);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newAdmin = new this.userModel({
            userName,
            email,
            password: hashedPassword,
            role: 'Admin',
        });

        return newAdmin.save();
    }

    //TODO : find all admns
    async findAllAdmins(): Promise<User[]> {
        return this.userModel.find({ role: 'Admin' });
    }

    //TODO : find all users
    async findAllUsers(): Promise<User[]> {
        return this.userModel.find({ role: 'User' });
    }

}
