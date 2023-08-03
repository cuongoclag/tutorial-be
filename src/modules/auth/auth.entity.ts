import { IsNotEmpty, IsString } from 'class-validator'
import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm'

@Entity({ name: 'auth' })
export class AuthEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string

  @Column()
  @IsNotEmpty()
  @IsString()
  userName: string

  @Column()
  @IsNotEmpty()
  @IsString()
  passWord: string

  @Column()
  @IsString()
  @IsNotEmpty()
  name: string

  @Column()
  @IsNotEmpty()
  @IsString()
  email: string

  @Column()
  @IsNotEmpty()
  dateOfBirth: Date

  @Column()
  @IsNotEmpty()
  @IsString()
  refreshToken: string
}
