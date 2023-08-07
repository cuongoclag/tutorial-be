import {
  ConflictException,
  Get,
  HttpException,
  HttpStatus,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
  UseGuards
} from '@nestjs/common'
import { AuthenticationDto } from './dtos/authentication.dto'
import { RefreshTokenDto } from './dtos/refresh-token.dto'

import { InjectRepository } from '@nestjs/typeorm'
import { AuthEntity } from './auth.entity'
import { Repository } from 'typeorm'
import { RegisterDto } from './dtos/register.dto'
import * as bcrypt from 'bcrypt'
import messages, { throwResourceException } from '../../common/messages'
import { JwtService } from '@nestjs/jwt'
import { RegisterResponseDto } from './dtos/register-response.dto'
import { JwtPayload } from './dtos/jwt-payload'
import { SignInResponse } from './dtos/login-response.dto'
import { ApiBearerAuth, ApiOperation } from '@nestjs/swagger'
import { AuthGuard } from '@nestjs/passport'
import { UserRole } from '../../common/common.enum'
import { resourceLimits } from 'worker_threads'

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(AuthEntity)
    private readonly authRepository: Repository<AuthEntity>,
    private jwtService: JwtService
  ) {}

  checkPassword(passWord: string, confirmPassword: string) {
    if (passWord !== confirmPassword) {
      throw new ConflictException(messages.PASSWORD_CONFIRMPASSWORD_DIFFERENT)
    }

    const strongPasswordRegex = /(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\dA-Za-z])(?=.{12,})/

    // return an array if password provided is valid, return null if invalid
    const ap = passWord.match(strongPasswordRegex)
    const message = null

    if (!ap) {
      throw new ConflictException(messages.PASSWORD_IS_WEEK)
    }

    return message
  }

  checkEmail(gmail: string) {
    const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

    const em = gmail.match(emailValid)
    const message = null

    if (!em) {
      console.log('run 44')
      throw new ConflictException(messages.EMAIL_INVALID)
    }

    return message
  }

  async existingUser(email: string) {
    const existingUser = await this.authRepository.findOne({ where: { email } })

    if (existingUser) {
      throw new HttpException(
        messages.ResourceMakeError(messages.USERNAME_IS_ALREADY, messages.HTTP_ERROR_CODE_BAD_REQUEST),
        HttpStatus.NOT_FOUND
      )
    }
  }

  async signUp(authDto: RegisterDto): Promise<RegisterResponseDto> {
    const { confirmPassword, passWord, dateOfBirth, email, fullName, roleId } = authDto
    console.log('🚀 ~ file: auth.service.ts:81 ~ AuthService ~ signUp ~ roleId:', roleId)

    await this.existingUser(email)

    if (confirmPassword !== null) {
      const passwordCheckMessage = this.checkPassword(confirmPassword as string, passWord as string)
      const emailValid = this.checkEmail(email as string)

      if (passwordCheckMessage == null && emailValid == null) {
        const salt = await bcrypt.genSalt()
        const hashedPassword = await bcrypt.hash(passWord, salt)
        const user = this.authRepository.create({
          email,
          dateOfBirth,
          fullName,
          passWord: hashedPassword
        })
        await this.authRepository.save(user)
      }
      return { email, passWord }
    } else {
      throw new HttpException(
        messages.ResourceMakeError(messages.USERNAME_IS_ALREADY, messages.HTTP_ERROR_CODE_BAD_REQUEST),
        HttpStatus.NOT_FOUND
      )
    }
  }

  async signIn(authDto: AuthenticationDto): Promise<SignInResponse> {
    const { email, passWord } = authDto
    const user = await this.authRepository.findOne({ where: { email } })

    if (user && (await bcrypt.compare(passWord, user?.passWord as string))) {
      const payload: JwtPayload = { id: user.id, email: user.email }

      return this.generateToken(payload)
    } else {
      throw new HttpException(
        messages.ResourceForbidden(messages.WRONG_PASSWORD, messages.HTTP_ERROR_CODE_BAD_REQUEST),
        HttpStatus.BAD_REQUEST
      )
    }
  }

  async refreshToken(refresh_token: string) {
    try {
      const verify = await this.jwtService.verifyAsync(refresh_token, {
        secret: 'topSecret51'
      })
      const checkExitToken = await this.authRepository.findOneBy({ email: verify.email, refresh_token })

      if (checkExitToken) {
        return this.generateToken({ id: verify.id, email: verify.email })
      } else {
        throw new HttpException(
          messages.ResourceForbidden(messages.TOKEN_INVALID, messages.HTTP_ERROR_CODE_BAD_REQUEST),
          HttpStatus.BAD_REQUEST
        )
      }
      console.log(verify)
    } catch (error) {
      throw new HttpException(
        messages.ResourceForbidden(messages.TOKEN_INVALID, messages.HTTP_ERROR_CODE_BAD_REQUEST),
        HttpStatus.BAD_REQUEST
      )
    }
  }

  async getUser() {
    return '123'
  }

  async generateToken(payload: JwtPayload) {
    const accessToken: string = await this.jwtService.signAsync(payload)
    const refresh_token: string = await this.jwtService.signAsync(payload, {
      secret: 'topSecret51',
      expiresIn: 3600
    })
    await this.authRepository.update({ email: payload.email }, { refresh_token: refresh_token })

    return { accessToken, refresh_token }
  }

  async getUserById(id: string) {
    console.log('run 134', id)
    const result = await this.authRepository
      .createQueryBuilder('auth')
      .leftJoin('auth.roleId', 'role')
      .select(['role', 'auth'])
      .where('auth.id = :id', { id })
      .getRawOne()
    console.log('🚀 ~ file: auth.service.ts:133 ~ AuthService ~ getUserById ~ result:', result)
    return result
  }
}
