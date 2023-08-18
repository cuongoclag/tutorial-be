import { IsNotEmpty, IsString } from 'class-validator'
import { RoleEntity } from '../roles/role.entity'
import { Column, Entity, JoinColumn, ManyToOne, OneToOne, PrimaryGeneratedColumn } from 'typeorm'
import { TeacherEntity } from '../teachers/teacher.entity'

@Entity({ name: 'auth' })
export class AuthEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string

  @Column()
  @IsNotEmpty()
  @IsString()
  password: string

  @Column()
  @IsString()
  @IsNotEmpty()
  fullName: string

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
  refresh_token: string

  @ManyToOne(() => RoleEntity, (role) => role.auth)
  @JoinColumn({
    name: 'role_id'
  })
  roleId: RoleEntity

  @OneToOne(() => TeacherEntity, (teacher) => teacher.auth_id)
  // @JoinColumn({ name: 'auth_id' })
  teacher: TeacherEntity
}
