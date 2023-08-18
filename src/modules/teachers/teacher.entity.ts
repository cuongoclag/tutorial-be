import { IsNotEmpty } from 'class-validator'
import { AbstractEntity } from '../../common/abstract.entity'
import { Column, Entity, JoinColumn, OneToOne } from 'typeorm'
import { TeacherDto } from './dto/teacher.dto'
import { AuthEntity } from '../auth/auth.entity'

@Entity({ name: 'teacher' })
export class TeacherEntity extends AbstractEntity<TeacherDto> {
  @Column({ type: 'decimal', precision: 6, scale: 2, nullable: true })
  hourly_rate?: number

  @OneToOne(() => AuthEntity)
  @JoinColumn({
    name: 'auth_id'
  })
  auth_id: AuthEntity
}
