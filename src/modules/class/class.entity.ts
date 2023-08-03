import { IsNotEmpty } from 'class-validator'
import { AbstractEntity } from '../../common/abstract.entity'
import { Column, Entity } from 'typeorm'
import { ClassDto } from './dtos/class.dto'

@Entity({ name: 'class' })
export class ClassEntity extends AbstractEntity<ClassDto> {
  @Column()
  @IsNotEmpty()
  room_number: string

  @Column()
  @IsNotEmpty()
  capacity: string
}
