import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpException,
  HttpStatus,
  Param,
  Post,
  UseGuards
} from '@nestjs/common'
import { AuthService } from './auth.service'
import { ApiBearerAuth, ApiBody, ApiCreatedResponse, ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger'
import { AuthenticationDto } from './dtos/authentication.dto'
import { RegisterResponseDto } from './dtos/register-response.dto'
import { RefreshTokenDto } from './dtos/refresh-token.dto'
import { RegisterDto } from './dtos/register.dto'
import { AuthEntity } from './auth.entity'
import { SignInResponse } from './dtos/login-response.dto'

import { UserRole } from '../../common/common.enum'
import { AuthGuard } from '../../guards/auth.guard'
import { getAllResponse } from './dtos/auth.dto'
import { DeleteUsersDto } from './dtos/deleteUser.dto'

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
  async getAllUser() {
    return this.authService.getUser()
  }

  @Delete('delete')
  @ApiOperation({ summary: 'Delete user' })
  @ApiBearerAuth()
  @ApiOkResponse({
    type: DeleteUsersDto,
    description: 'Delete is success'
  })
  @UseGuards(AuthGuard)
  async deleteUsers(@Body() dto: DeleteUsersDto) {
    const { emails } = dto

    if (emails.length === 1) {
      return await this.authService.deleteUserByEmail(emails[0])
    } else {
      return await this.authService.deleteUsersByEmails(emails)
    }
  }
}
