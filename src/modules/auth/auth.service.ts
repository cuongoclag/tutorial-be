import { isArray } from 'lodash'
import { ConflictException, HttpException, HttpStatus, Injectable, NotFoundException } from '@nestjs/common'
import { AuthenticationDto } from './dtos/authentication.dto'

import { InjectRepository } from '@nestjs/typeorm'
import { AuthEntity } from './auth.entity'
import { Repository } from 'typeorm'
import { RegisterDto } from './dtos/register.dto'
import * as bcrypt from 'bcrypt'
import messages from '../../common/messages'
import { JwtService } from '@nestjs/jwt'
import { RegisterResponseDto } from './dtos/register-response.dto'
import { JwtPayload } from './dtos/jwt-payload'
import { SignInResponse } from './dtos/signInReponse.dto'
import { getAllResponse } from './dtos/auth.dto'
import { RolesService } from '../roles/roles.service'
import { UpdateUserDto } from './dtos/updateUser.dto'
import { TeacherEntity } from '../teachers/teacher.entity'
import { stringify } from 'querystring'
import { UserRole } from '../../common/common.enum'

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(AuthEntity)
    private readonly authRepository: Repository<AuthEntity>,
    private readonly roleRepository: RolesService,
    private jwtService: JwtService,

    @InjectRepository(TeacherEntity)
    private readonly teacherRepository: Repository<TeacherEntity>
  ) {}

  checkPassword(password: string, confirmPassword: string) {
    if (password !== confirmPassword) {
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

  checkEmail(email: string) {
    const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

    const em = email.match(emailValid)
    const message = null

    if (!em) {
      throw new ConflictException(messages.EMAIL_INVALID)
    }

    return message
  }

  async signUp(authDto: RegisterDto): Promise<RegisterResponseDto> {
    const { confirmPassword, password, dateOfBirth, email, fullName, roleId, hourlyRate } = authDto

    if (confirmPassword !== null) {
      const role = await this.roleRepository.getRoleById(roleId)
      const existingUser = await this.authRepository.findOne({ where: { email } })

      if (role === null) {
        throw new HttpException(
          messages.ResourceMakeError(messages.ROLE_NOT_EXIT, messages.HTTP_ERROR_CODE_BAD_REQUEST),
          HttpStatus.NOT_FOUND
        )
      }

      if (existingUser) {
        throw new HttpException(
          messages.ResourceMakeError(messages.USERNAME_IS_ALREADY, messages.HTTP_ERROR_CODE_BAD_REQUEST),
          HttpStatus.NOT_FOUND
        )
      }

      const passwordCheckMessage = this.checkPassword(confirmPassword as string, password as string)

      const emailValid = this.checkEmail(email)

      if (passwordCheckMessage === null && emailValid === null) {
        const salt = await bcrypt.genSalt()
        const hashedPassword = await bcrypt.hash(password, salt)

        const newTeacher = new TeacherEntity()
        const newAuth = new AuthEntity()

        newAuth.password = hashedPassword
        newAuth.email = email
        newAuth.roleId = role
        newAuth.dateOfBirth = dateOfBirth
        newAuth.fullName = fullName
        newAuth.refresh_token = ''

        newTeacher.auth_id = newAuth
        try {
          if (hourlyRate) {
            newTeacher.createdBy = email
            newTeacher.updatedBy = email
            newTeacher.hourly_rate = hourlyRate
            await this.teacherRepository.save(newTeacher)

            const newTeacherId = newTeacher.id

            newAuth.teacher = newTeacher
            await this.authRepository.save(newAuth)
          } else {
            await this.authRepository.save(newAuth)
          }
        } catch (error) {
          console.log('🚀 ~ file: auth.service.ts:123 ~ AuthService ~ signUp ~ error:', error)
        }
      }
      return { email, password }
    } else {
      throw new HttpException(
        messages.ResourceMakeError(messages.USERNAME_IS_ALREADY, messages.HTTP_ERROR_CODE_BAD_REQUEST),
        HttpStatus.NOT_FOUND
      )
    }
  }

  async signIn(authDto: AuthenticationDto): Promise<SignInResponse> {
    const { email, password } = authDto
    const user = await this.authRepository.findOne({ where: { email } })

    if (user && (await bcrypt.compare(password, user?.password as string))) {
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
    } catch (error) {
      throw new HttpException(
        messages.ResourceForbidden(messages.TOKEN_INVALID, messages.HTTP_ERROR_CODE_BAD_REQUEST),
        HttpStatus.BAD_REQUEST
      )
    }
  }

  async getUser(): Promise<getAllResponse[]> {
    const result: AuthEntity[] = await this.authRepository
      .createQueryBuilder('auth')
      .leftJoin('auth.roleId', 'role')
      .select(['role', 'auth'])
      .getMany()

    if (result.length === 0) {
      throw new HttpException(
        messages.ResourceForbidden(messages.GET_ALL_USER_FAILED, messages.HTTP_ERROR_CODE_BAD_REQUEST),
        HttpStatus.NOT_FOUND
      )
    }

    const getUserPromises = result.map(async (user) => {
      const { email, dateOfBirth, fullName, roleId } = user

      const allUser: getAllResponse = {
        roleName: roleId.roleName,
        fullName,
        email,
        dateOfBirth
      }

      return allUser
    })

    const allUsers = await Promise.all(getUserPromises)

    return allUsers
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
    const result = await this.authRepository
      .createQueryBuilder('auth')
      .leftJoin('auth.roleId', 'role')
      .select(['role', 'auth'])
      .where('auth.id = :id', { id })
      .getRawOne()

    return result
  }

  async deleteUserByEmail(email: string): Promise<string> {
    const user = await this.authRepository.findOne({ where: { email }, relations: ['teacher'] })
    console.log('🚀 ~ file: auth.service.ts:227 ~ AuthService ~ deleteUserByEmail ~ user:', user)

    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND)
    }

    if (user.teacher) {
      await this.teacherRepository.remove(user.teacher)
    }

    await this.authRepository.remove(user)

    return 'User has been deleted'
  }

  async deleteUsersByEmails(emails: string[]): Promise<string> {
    const deletePromises = emails.map(async (email) => {
      await this.deleteUserByEmail(email)
    })

    await Promise.all(deletePromises)

    return 'Người dùng đã được xoá'
  }

  async updateUser(updateUserDto: UpdateUserDto) {
    const { dateOfBirth, email, fullName } = updateUserDto

    const user = await this.authRepository.findOne({ where: { email } })
    if (user) {
      user.fullName = fullName
      user.dateOfBirth = dateOfBirth
      await this.authRepository.save(user)
      return user
    } else {
      throw new HttpException(
        messages.ResourceForbidden(messages.EMAIL_INVALID, messages.HTTP_ERROR_CODE_BAD_REQUEST),
        HttpStatus.NOT_FOUND
      )
    }
  }

  async getProfile(userProfileId: string): Promise<getAllResponse> {
    const id = userProfileId
    const profile = await this.authRepository
      .createQueryBuilder('auth')
      .leftJoin('auth.roleId', 'role')
      .select(['role', 'auth'])
      .where('auth.id = :id', { id })
      .getRawOne()
    console.log('🚀 ~ file: auth.service.ts:271 ~ AuthService ~ getProfile ~ profile:', profile)

    if (profile.role_role_name === UserRole.TEACHER) {
      console.log('run123')
      const teacherProfile = await this.authRepository
        .createQueryBuilder('auth')
        .leftJoin('auth.teacher', 'teacherId')
        .select(['teacherId', 'auth'])
        //.where('auth.teacher_id = :teacherId', 'teacher.id')
        .getRawOne()

      console.log('🚀 ~ file: auth.service.ts:278 ~ AuthService ~ getProfile ~ teacherProfile:', teacherProfile)
    } else {
    }

    const result: getAllResponse = {
      roleName: profile.role_description,
      fullName: profile.auth_full_name,
      email: profile.auth_email,
      dateOfBirth: profile.auth_date_of_birth
    }
    return result
  }
}
