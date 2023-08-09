import { IsArray, IsOptional, IsString } from 'class-validator'

export class DeleteUsersDto {
  @IsArray()
  @IsString({ each: true })
  emails: string[]

  @IsOptional()
  @IsString()
  email?: string
}
