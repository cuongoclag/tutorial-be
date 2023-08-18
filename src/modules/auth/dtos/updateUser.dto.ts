import { ApiProperty } from '@nestjs/swagger'
import { IsDateString, IsString } from 'class-validator'

export class UpdateUserDto {
  @IsString()
  @ApiProperty()
  fullName: string

  @IsString()
  @ApiProperty()
  email: string

  @ApiProperty()
  @IsDateString()
  dateOfBirth: Date
}
