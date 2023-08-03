import { ApiPropertyOptional } from '@nestjs/swagger'

import type { AbstractEntity } from '../abstract.entity'
import { UUID } from 'crypto'

export class AbstractDto {
  @ApiPropertyOptional()
  id?: UUID

  constructor(entity: AbstractEntity, options?: { excludeFields?: boolean }) {
    if (!options?.excludeFields) {
      this.id = entity.id
    }
  }
}
