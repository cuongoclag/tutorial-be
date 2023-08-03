import { ApiProperty } from '@nestjs/swagger'
import { IsDateString, IsString } from 'class-validator'

export class NewPasswordDto {
  @ApiProperty()
  @IsString()
  userName: string

  @ApiProperty()
  @IsString()
  passWord: string

  @ApiProperty()
  @IsString()
  newPassword?: string

  @IsString()
  @ApiProperty()
  name: string

  @IsString()
  @ApiProperty()
  email: string

  @ApiProperty()
  @IsDateString()
  dateOfBirth: string

  @IsString()
  @ApiProperty()
  refreshToken: string
}
