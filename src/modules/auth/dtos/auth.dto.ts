import { ApiProperty } from '@nestjs/swagger'

export class getAllResponse {
  @ApiProperty()
  role_name: string

  @ApiProperty()
  fullName: string

  @ApiProperty()
  email: string

  @ApiProperty()
  dateOfBirth: Date
}
