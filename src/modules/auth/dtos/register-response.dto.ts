import { ApiProperty } from '@nestjs/swagger'
import { AbstractDto } from '../../../common/dtos/abstract.dto'
import { IsString } from 'class-validator'

export class RegisterResponseDto {
  @ApiProperty()
  @IsString()
  email: string

  @ApiProperty()
  @IsString()
  passWord: string
}
