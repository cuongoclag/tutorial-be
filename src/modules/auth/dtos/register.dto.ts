import { ApiProperty } from '@nestjs/swagger'
import { IsDateString, IsString } from 'class-validator'
import { UserRole } from '../../../common/common.enum'

export class RegisterDto {
  @ApiProperty()
  @IsString()
  passWord: string

  @ApiProperty()
  @IsString()
  confirmPassword?: string

  @IsString()
  @ApiProperty()
  fullName: string

  @IsString()
  @ApiProperty()
  email: string

  @ApiProperty()
  @IsDateString()
  dateOfBirth: string

  @IsString()
  @ApiProperty()
  roleId: UserRole.ADMIN
}