import { ConflictException, HttpException, HttpStatus, Injectable, InternalServerErrorException } from '@nestjs/common'
import { AuthenticationDto } from './dtos/authentication.dto'
import { RefreshTokenDto } from './dtos/refresh-token.dto'
import * as bcrypt from 'bcrypt'
import { InjectRepository } from '@nestjs/typeorm'
import { AuthEntity } from './auth.entity'
import { Repository } from 'typeorm'
import { NewPasswordDto } from './dtos/new-password.dto'
import { promises } from 'readline'
import messages, { throwResourceException } from '../../common/messages'

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(AuthEntity)
    private readonly authRepository: Repository<AuthEntity>
  ) {}

  checkPassword(password: string, newPassword: string) {
    if (password !== newPassword) {
      throw new ConflictException(messages.PASSWORD_CONFIRMPASSWORD_DIFFERENT)
    }

    const strongPasswordRegex = /(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\dA-Za-z])(?=.{12,})/

    // return an array if password provided is valid, return null if invalid
    const ap = password.match(strongPasswordRegex)
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

  async existingUser(userName: string) {
    const existingUser = await this.authRepository.findOne({ where: { userName } })

    if (existingUser) {
      throw new HttpException(
        messages.ResourceMakeError(messages.USERNAME_IS_ALREADY, messages.HTTP_ERROR_CODE_BAD_REQUEST),
        HttpStatus.NOT_FOUND
      )
    }
  }

  async signUp(authDto: NewPasswordDto) {
    const { newPassword, passWord, userName, dateOfBirth, email, name, refreshToken } = authDto

    await this.existingUser(userName)

    if (newPassword !== null) {
      const passwordCheckMessage = this.checkPassword(newPassword as string, passWord as string)

      const emailValid = this.checkEmail(email as string)

      if ((passwordCheckMessage && emailValid) == null) {
        console.log('run 47')
        const salt = await bcrypt.genSalt()
        const hashedPassword = await bcrypt.hash(passWord, salt)
        const user = this.authRepository.create({
          userName,
          passWord: hashedPassword,
          dateOfBirth,
          email,
          name,
          refreshToken
        })
        await this.authRepository.save(user)
      }
    } else {
      console.log('run 93')
      throw new HttpException(
        messages.ResourceMakeError(messages.USERNAME_IS_ALREADY, messages.HTTP_ERROR_CODE_BAD_REQUEST),
        HttpStatus.NOT_FOUND
      )
    }
  }
}
