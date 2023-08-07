import { AuthenticationDto } from './dtos/authentication.dto'

import { InjectRepository } from '@nestjs/typeorm'
import { Injectable, UnauthorizedException } from '@nestjs/common'
import { PassportStrategy } from '@nestjs/passport'
import { ExtractJwt, Strategy } from 'passport-jwt'
import { AuthEntity } from './auth.entity'
import { Repository } from 'typeorm'

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @InjectRepository(AuthEntity)
    private readonly authRepository: Repository<AuthEntity>
  ) {
    super({
      secretOrKey: 'topSecret51',
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken()
    })
  }

  async validate(payload: AuthenticationDto): Promise<AuthenticationDto> {
    const { email } = payload
    const user = await this.authRepository.findOne({
      where: { email }
    })
    if (!user) {
      throw new UnauthorizedException()
    }
    return user
  }
}
