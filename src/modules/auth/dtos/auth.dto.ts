import { ApiProperty } from '@nestjs/swagger'

export class getAllResponse {
  @ApiProperty()
  roleName: string

  @ApiProperty()
  fullName: string

  @ApiProperty()
  email: string

  @ApiProperty()
  dateOfBirth: Date
}
