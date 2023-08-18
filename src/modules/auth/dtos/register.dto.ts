import { IsDateString, IsString, IsNumber, IsOptional } from 'class-validator'
import { ApiProperty } from '@nestjs/swagger'

export class RegisterDto {
  @ApiProperty()
  @IsString()
  password: string

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
  dateOfBirth: Date

  refresh_token: string

  @ApiProperty()
  @IsString()
  roleId: string

  @ApiProperty({ required: false })
  @IsOptional()
  @IsNumber()
  hourlyRate?: number
}
