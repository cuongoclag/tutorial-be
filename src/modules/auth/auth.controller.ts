import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common'
import { AuthService } from './auth.service'
import { ApiBearerAuth, ApiBody, ApiCreatedResponse, ApiOkResponse, ApiOperation } from '@nestjs/swagger'
import { AuthenticationDto } from './dtos/authentication.dto'
import { RegisterResponseDto } from './dtos/register-response.dto'
import { RefreshTokenDto } from './dtos/refresh-token.dto'
import { RegisterDto } from './dtos/register.dto'
import { AuthEntity } from './auth.entity'
import { SignInResponse } from './dtos/login-response.dto'

import { UserRole } from '../../common/common.enum'
import { AuthGuard } from '../../guards/auth.guard'

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @ApiOperation({ summary: 'Create A New User' })
  @ApiBody({
    type: RegisterDto
  })
  @ApiOkResponse({
    type: RegisterResponseDto,
    description: 'Register success'
  })
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
  @UseGuards(AuthGuard)
  async getAllUser() {
    return this.authService.getUser()
  }
}
