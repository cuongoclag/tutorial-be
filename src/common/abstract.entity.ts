import { IsNotEmpty } from 'class-validator'
import { Column, CreateDateColumn, PrimaryGeneratedColumn, UpdateDateColumn } from 'typeorm'

import type { AbstractDto } from './dtos/abstract.dto'
import { UUID } from 'crypto'
import { Constructor } from 'types'

export interface IAbstractEntity<DTO extends AbstractDto, O = never> {
  id: UUID
  createdAt: Date
  updatedAt: Date
  createdBy: string
  updatedBy: string
  toDto(options?: O): DTO
}

export abstract class AbstractEntity<DTO extends AbstractDto = AbstractDto, O = never>
  implements IAbstractEntity<DTO, O>
{
  @PrimaryGeneratedColumn('uuid')
  id: UUID

  @CreateDateColumn({
    type: 'timestamp'
  })
  @IsNotEmpty()
  createdAt: Date

  @UpdateDateColumn({
    type: 'timestamp',
    nullable: true
  })
  updatedAt: Date

  @Column({ nullable: false })
  @IsNotEmpty()
  createdBy: string

  @Column({ nullable: false })
  @IsNotEmpty()
  updatedBy: string

  private dtoClass?: Constructor<DTO, [AbstractEntity, O?]>

  toDto(options?: O): DTO {
    const dtoClass = this.dtoClass

    if (!dtoClass) {
      throw new Error(`You need to use @UseDto on class (${this.constructor.name}) be able to call toDto function`)
    }

    return new dtoClass(this, options)
  }
}
