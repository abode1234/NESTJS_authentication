// src/users/users.controller.ts
import { Controller, Post, Body, Get } from '@nestjs/common';
import { UsersService } from './users.service';
import { RegisterUserDto } from './dto/register-user.dto';

@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  @Post('register')
  async register(@Body() registerUserDto: RegisterUserDto) {
    await this.usersService.registerUser(registerUserDto);
    return { message: 'User registered successfully' };
  }

  @Post('register-admin')
  async registerAdmin(@Body() registerUserDto: RegisterUserDto) {
    await this.usersService.registerAdmin(registerUserDto);
    return { message: 'Admin registered successfully' };
  }


  @Get('admins')
  async findAllAdmins(): Promise<RegisterUserDto[]> {
    return this.usersService.findAllAdmins();
  }

  @Get('users')
  async findAllUsers(): Promise<RegisterUserDto[]> {
    return this.usersService.findAllUsers();
  }

}
