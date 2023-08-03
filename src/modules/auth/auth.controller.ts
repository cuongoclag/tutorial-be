import { Body, Controller, Post } from '@nestjs/common'
import { AuthService } from './auth.service'
import { ApiBody, ApiOkResponse, ApiOperation } from '@nestjs/swagger'
import { AuthenticationDto } from './dtos/authentication.dto'
import { AuthenticationResponseDto } from './dtos/authentication-response.dto'
import { RefreshTokenDto } from './dtos/refresh-token.dto'
import { NewPasswordDto } from './dtos/new-password.dto'

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @ApiOperation({ summary: 'Create A New User' })
  @ApiBody({
    type: NewPasswordDto
  })
  @ApiOkResponse({
    type: NewPasswordDto,
    description: 'User access token'
  })
  async createNewPassword(@Body() authDto: NewPasswordDto) {
    return this.authService.signUp(authDto)
  }
}
