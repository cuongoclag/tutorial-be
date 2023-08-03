import { Module } from '@nestjs/common';

import { HealthCheckerController } from './health-checker.controller';
import { HealthCheckerService } from './health-checker.service';

@Module({
  providers: [HealthCheckerService],
  controllers: [HealthCheckerController],
})
export class HealthCheckerModule {}
