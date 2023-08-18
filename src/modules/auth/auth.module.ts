import { Module } from '@nestjs/common'

import { AuthController } from './auth.controller'
import { AuthService } from './auth.service'
import { TypeOrmModule } from '@nestjs/typeorm'
import { AuthEntity } from './auth.entity'
import { PassportModule } from '@nestjs/passport'
import { JwtModule } from '@nestjs/jwt'
import { JwtStrategy } from './jwt.strategy'
import { RoleEntity } from '../roles/role.entity'
import { RolesService } from '../roles/roles.service'
import { TeacherEntity } from '../teachers/teacher.entity'
import { TeachersService } from '../teachers/teachers.service'

@Module({
  imports: [
    TypeOrmModule.forFeature([AuthEntity, RoleEntity, TeacherEntity]),
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({
      secret: 'topSecret51',
      signOptions: { expiresIn: 3600 }
    })
  ],
  providers: [AuthService, JwtStrategy, RolesService, TeachersService],
  controllers: [AuthController],
  exports: [JwtStrategy, PassportModule]
})
export class AuthModule {}
