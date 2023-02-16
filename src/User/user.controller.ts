import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserService } from './user.service';
import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
import { ValidateGuard } from './guards/jwt.guard';

@Controller('/users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post()
  async create(@Body() createUserDto: CreateUserDto) {
    createUserDto.password = await bcrypt.hash(createUserDto.password, 10);
    return this.userService.create(createUserDto);
  }

  @Post('/login')
  async login(
    @Body() loginUserDto: LoginUserDto,
    @Req() req,
    @Res({ passthrough: true }) res: Response,
  ) {
    return await this.userService.login(loginUserDto, req, res);
  }

  @Get('/id/:id')
  async findAll(@Param('id') id: string) {
    return await this.userService.findUserById(Number(id));
  }

  @Patch('/id/:id')
  async update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return await this.userService.updateById(Number(id), updateUserDto);
  }

  @Delete('/delete/:id')
  remove(@Param('id') id: string) {
    return 'vmi';
  }

  
  @Get('/secure-endpoint')
  @UseGuards(ValidateGuard)
  async secure(@Req() req) {
    return 'this is secure';
  } 

  @Get('/login')
  async loginPage(@Req() req, @Res() res) {
    return await this.userService.login(null, req, res);
  }
} 
