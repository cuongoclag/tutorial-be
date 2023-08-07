import { ApiHideProperty, ApiProperty } from '@nestjs/swagger'
import { IsString } from 'class-validator'

export class RoleDto {
  @ApiProperty()
  @IsString()
  roleName: string

  @ApiProperty()
  @IsString()
  description: string
}
