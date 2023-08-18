import { ApiHideProperty, ApiProperty } from '@nestjs/swagger'
import { IsString } from 'class-validator'

export class AuthenticationDto {
  @ApiProperty()
  @IsString()
  email: string

  @ApiProperty()
  @IsString()
  password: string
}
