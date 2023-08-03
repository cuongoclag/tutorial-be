import { ApiHideProperty, ApiProperty } from '@nestjs/swagger'
import { IsString } from 'class-validator'

export class AuthenticationDto {
  @ApiProperty()
  @IsString()
  userName: string

  @ApiProperty()
  @IsString()
  passWord: string

  @ApiHideProperty()
  @IsString()
  newPassword?: string
}
