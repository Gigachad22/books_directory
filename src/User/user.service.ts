/* eslint-disable prettier/prettier */
import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { LoginUserDto } from './dto/login-user.dto';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { User } from '@prisma/client';
import * as moment from 'moment';
import { UserDetails } from './interfaces/userDetails.interface';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuid } from 'uuid';
import * as UAParser from 'ua-parser-js';

@Injectable()
export class UserService {
  constructor(
    private prisma: PrismaService,
    private configService: ConfigService,
    private jwtService: JwtService,
  ) {}

  /**
   * Felhasználó szempontjából nem fontos adatok levágása.
   * @param user
   * @returns
   */
  _trimData(user: User): UserDetails {
    return {
      name: user.name,
      email: user.email,
      phone: user.phone,
      role: user.role,
    };
  }

  /**
   * JWT Refresh Token-t generál a felhasználónak és elmenti ezt,
   * illetve a lejárati dátumot (7 nap) az adatbázisba.
   * @param user
   * @returns
   */
  async _newRefreshToken(userID: number): Promise<string> {
    
    // Pontosan 7 nappal később
    const refreshExpiresAt: string = moment()
      .add(7, 'days')
      .toDate()
      .toISOString();
    const refreshToken: string = uuid();
    await this.prisma.session.create({
      data: {
        refreshToken: refreshToken,
        refreshTokenExp: refreshExpiresAt,
        user: {
          connect: {
            id: userID,
          },
        },
      },
    });

    return refreshToken;
  }

  /**
   * Email alapján ellenőrzi, hogy létezik-e az adatbázisban az adott felhasználó.
   * @param user
   * @returns
   */
  async _checkIfUserExists(email: string): Promise<boolean> {
    if (
      (await this.prisma.user.count({
        where: { email: email },
      })) > 0
    ) {
      return true;
    }
    return false;
  }

  /**
   * Email cím alapján nézi meg az adatbázisban, hogy a kapott Refresh Token valid-e,
   * ha igen, akkor új access token-t generál és visszaadja.
   * @param email
   * @param refreshToken
   * @returns
   */
  async _regenerateAccessToken(refreshToken: string): Promise<string | null> {
    const currentDate = new Date().toISOString();

    const foundedSession = await this.prisma.session.findFirst({
      where: {
        refreshToken: refreshToken,
        refreshTokenExp: {
          gte: currentDate,
        },
      },
      select: {
        user: true,
      },
    });
    const user: User = foundedSession?.user;
    if (!user) {
      return null;
    }
    const user_no_pass: UserDetails = this._trimData(user);
    const newAccessToken: string = await this.jwtService.signAsync(
      user_no_pass,
    );
    return newAccessToken;
  }

  /**
   * Felhasználó regisztrációja.
   * @param createUserDto
   * @returns
   */
  async create(createUserDto: CreateUserDto) {
    if (await this._checkIfUserExists(createUserDto.email)) {
      throw new ForbiddenException('User already exists');
    } else {
      return this._trimData(
        await this.prisma.user.create({ data: createUserDto }),
      );
    }
  }

  /**
   * Felhasználó bejelentkezik és autentikálja magát => kap új Access és Refresh Tokent.
   * @param loginUserDto
   * @param res
   * @returns
   */
  async login(loginUserDto: LoginUserDto, req, res) {
    if (!(await this._checkIfUserExists(loginUserDto.email))) {
      throw new ForbiddenException('User does not exist');
    } else {
      const user = await this.prisma.user.findFirst({
        where: { email: loginUserDto.email },
      });
      const hashedPassword: string = user.password;
      if (!(await bcrypt.compare(loginUserDto.password, hashedPassword)))
        throw new UnauthorizedException('Password is not correct');

      const user_no_pass = this._trimData(user);
      const token = await this.jwtService.signAsync(user_no_pass);
      const refreshToken = await this._newRefreshToken(user.id);
      const secretData = {
        token,
        refreshToken,
      };

      res.cookie('auth-cookie', secretData, { httpOnly: true });
      return user_no_pass;
    }
  }

  /**
   * Paraméterként kapott id alapján megkeresi a felhasználót és visszaadja a lecsupaszított adatait.
   * @param id
   * @returns
   */
  async findUserById(id: number): Promise<UserDetails> {
    const user = await this.prisma.user.findUnique({
      where: {
        id: id,
      },
    });
    return this._trimData(user);
  }

  /**
   * Id alapján frissít egy rekordot az adatbázisban.
   * @param id
   * @param updateUserDto
   * @returns
   */
  async updateById(id: number, updateUserDto: UpdateUserDto) {
    const user = await this.prisma.user.update({
      where: { id },
      data: updateUserDto,
    });
    return this._trimData(user);
  }
}
