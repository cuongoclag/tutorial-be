import { ApiPropertyOptional } from '@nestjs/swagger'
import { AbstractDto } from '../../../common/dtos/abstract.dto'

export class ClassDto extends AbstractDto {
  @ApiPropertyOptional()
  room_number: string

  @ApiPropertyOptional()
  capacity: string
}
