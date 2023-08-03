import { ApiProperty } from '@nestjs/swagger'
import { AbstractDto } from '../../../common/dtos/abstract.dto'
import { IsString } from 'class-validator'

export class AuthenticationResponseDto {
  @ApiProperty()
  @IsString()
  accessToken: string

  @ApiProperty()
  @IsString()
  idToken: string

  @ApiProperty()
  @IsString()
  refreshToken: string
}
