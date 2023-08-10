import { ArrayNotEmpty, IsArray, IsEmail, IsOptional, IsString } from 'class-validator'

export class DeleteUsersDto {
  @IsArray()
  @ArrayNotEmpty()
  @IsEmail({}, { each: true })
  emails: string[]
}
