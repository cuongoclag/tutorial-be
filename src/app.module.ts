import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { ScheduleModule } from '@nestjs/schedule'
import { TypeOrmModule } from '@nestjs/typeorm'
import { LoggerModule } from 'nestjs-pino'

import { AuthModule } from './modules/auth/auth.module'
import { ClassModule } from './modules/class/class.module'
import { ContractsModule } from './modules/contracts/contracts.module'
import { CourseEnrollmentsModule } from './modules/course-enrollments/course-enrollments.module'
import { CoursesModule } from './modules/courses/courses.module'
import { HealthCheckerModule } from './modules/health-checker/health-checker.module'
import { HealthCheckerService } from './modules/health-checker/health-checker.service'
import { LessonsModule } from './modules/lessons/lessons.module'
import { RolesModule } from './modules/roles/roles.module'
import { SalaryPaymentsModule } from './modules/salary-payments/salary-payments.module'
import { TeachersModule } from './modules/teachers/teachers.module'
import { TuitionReceiptsModule } from './modules/tuition-receipts/tuition-receipts.module'
import { ApiConfigService } from './shared/services/api-config.service'
import { SharedModule } from './shared/shared.module'

@Module({
  imports: [
    HealthCheckerModule,

    AuthModule,

    RolesModule,

    TeachersModule,

    ClassModule,

    CoursesModule,

    CourseEnrollmentsModule,

    ContractsModule,

    LessonsModule,

    SalaryPaymentsModule,

    TuitionReceiptsModule,

    ScheduleModule.forRoot(),
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env'
    }),
    LoggerModule.forRoot({
      pinoHttp: {
        level: process.env.LOG_LEVEL || 'debug',
        transport: {
          target: 'pino-pretty',
          options: {
            singleLine: true,
            messageFormat: '[{context}]: {msg}',
            ignore: 'pid,hostname,context,req,res,responseTime',
            translateTime: "yyyy-MM-dd'T'HH:mm:ss.l'Z'"
          }
        }
      }
    }),
    TypeOrmModule.forRootAsync({
      imports: [SharedModule],
      useFactory: (configService: ApiConfigService) => configService.getMysqlConfig,
      inject: [ApiConfigService]
    })
  ],
  providers: [HealthCheckerService]
})
export class AppModule {}
