import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpException,
  HttpStatus,
  Param,
  Patch,
  Post,
  Request,
  UseGuards
} from '@nestjs/common'
import { AuthService } from './auth.service'
import { ApiBearerAuth, ApiBody, ApiCreatedResponse, ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger'
import { AuthenticationDto } from './dtos/authentication.dto'
import { RegisterResponseDto } from './dtos/register-response.dto'
import { RegisterDto } from './dtos/register.dto'
import { AuthEntity } from './auth.entity'
import { SignInResponse } from './dtos/signInReponse.dto'

import { UserRole } from '../../common/common.enum'
import { AuthGuard } from '../../guards/auth.guard'
import { getAllResponse } from './dtos/auth.dto'
import { DeleteUsersDto } from './dtos/deleteUser.dto'
import { UpdateUserDto } from './dtos/updateUser.dto'
import { Roles } from '../../decorators/roles.decorator'

@Controller('auth')
@ApiTags('Auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @ApiOperation({ summary: 'Create A New User' })
  @ApiBody({
    type: RegisterDto
  })
  @ApiBearerAuth()
  @ApiOkResponse({
    type: RegisterResponseDto,
    description: 'Register success'
  })
  @UseGuards(AuthGuard)
  @Roles(UserRole.ADMIN)
  async register(@Body() authDto: RegisterDto): Promise<RegisterResponseDto> {
    return this.authService.signUp(authDto)
  }

  @Post('sign-in')
  @ApiOperation({ summary: 'Login' })
  @ApiBody({
    type: AuthenticationDto
  })
  @ApiOkResponse({
    type: SignInResponse,
    description: 'Login success'
  })
  async signIn(@Body() authDto: AuthenticationDto): Promise<SignInResponse> {
    return this.authService.signIn(authDto)
  }

  @Get('getUser')
  @ApiOperation({ summary: 'Get user' })
  @ApiBearerAuth()
  @ApiOkResponse({
    type: getAllResponse,
    description: 'Get all user success',
    isArray: true
  })
  @UseGuards(AuthGuard)
  @Roles(UserRole.ADMIN, UserRole.TEACHER)
  async getAllUser() {
    return this.authService.getUser()
  }

  @Get('profile')
  @ApiOperation({ summary: 'Get user profile' })
  @ApiBearerAuth()
  @ApiOkResponse({
    type: getAllResponse,
    description: 'Get user success'
  })
  @UseGuards(AuthGuard)
  @Roles(UserRole.ADMIN, UserRole.TEACHER, UserRole.STUDENT)
  async getProfile(@Request() req) {
    const userProfileId = req.user.auth_id

    return await this.authService.getProfile(userProfileId)
  }

  @Delete('delete')
  @ApiOperation({ summary: 'Delete user' })
  @ApiBearerAuth()
  @ApiOkResponse({
    type: DeleteUsersDto,
    description: 'Delete is success'
  })
  @Roles(UserRole.ADMIN)
  @UseGuards(AuthGuard)
  async deleteUsers(@Body() dto: DeleteUsersDto) {
    const { emails } = dto

    if (emails.length === 1) {
      return await this.authService.deleteUserByEmail(emails[0])
    } else {
      return await this.authService.deleteUsersByEmails(emails)
    }
  }

  @Post('updateUser')
  @ApiOperation({ summary: 'Update user' })
  @ApiBearerAuth()
  @ApiOkResponse({
    type: DeleteUsersDto,
    description: 'Update is success'
  })
  async updateUser(@Body() updateUserDto: UpdateUserDto) {
    this.authService.updateUser(updateUserDto)
  }
}
