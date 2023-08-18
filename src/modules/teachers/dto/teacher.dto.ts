import { ApiPropertyOptional } from '@nestjs/swagger'
import { AbstractDto } from '../../../common/dtos/abstract.dto'

export class TeacherDto extends AbstractDto {
  @ApiPropertyOptional()
  hourly_rate: number
}
