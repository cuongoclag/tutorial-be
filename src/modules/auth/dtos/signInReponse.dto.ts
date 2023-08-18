import { ApiProperty } from '@nestjs/swagger'
import { IsString } from 'class-validator'

export class SignInResponse {
  @ApiProperty()
  @IsString()
  accessToken: string
}
