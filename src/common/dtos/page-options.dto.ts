// import { NumberFieldOptional, StringFieldOptional } from '../../decorators'

// export class OptionSchedule {
//   @StringFieldOptional()
//   filterSchedule?: string
// }
// export class PageOptionsDto {
//   @NumberFieldOptional({
//     minimum: 1,
//     default: 1,
//     int: true
//   })
//   readonly page: number = 1

//   @NumberFieldOptional({
//     default: 0,
//     int: true
//   })
//   readonly pageSize: number = 0

//   get skip(): number {
//     return (this.page - 1) * this.pageSize || 0
//   }

//   @StringFieldOptional()
//   readonly search?: string

//   @StringFieldOptional()
//   readonly sortBy?: string

//   @StringFieldOptional()
//   readonly filter?: string
// }
