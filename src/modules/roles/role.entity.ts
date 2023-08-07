import { IsNotEmpty, IsString } from 'class-validator'
import { AuthEntity } from '../auth/auth.entity'
import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from 'typeorm'

@Entity({ name: 'role' })
export class RoleEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string

  @Column()
  @IsNotEmpty()
  @IsString()
  roleName: string

  @Column()
  @IsString()
  description: string

  @OneToMany(() => AuthEntity, (auth) => auth.roleId)
  auth: AuthEntity[]
}
