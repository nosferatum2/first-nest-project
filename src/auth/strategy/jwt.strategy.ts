import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) { // PassportStrategy name by default 'jwt'
  constructor(
    config: ConfigService,
    private readonly prismaService: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get('JWT_SECRET'),
    });

  }

  async validate(payload: {
    sub: number,
    email: string
  }) {

    const user = await this.prismaService.user.findUnique({ // user object from prisma
      where: {
        id: payload.sub
      }
    });

    delete user.hash

    return user;
  }
}
