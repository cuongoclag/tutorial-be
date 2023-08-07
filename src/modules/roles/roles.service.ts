import { Injectable } from '@nestjs/common'
import { RoleDto } from './dtos/role.dto'
import { Repository } from 'typeorm'
import { RoleEntity } from './role.entity'
import { InjectRepository } from '@nestjs/typeorm'

@Injectable()
export class RolesService {
  constructor(
    @InjectRepository(RoleEntity)
    private readonly roleRepository: Repository<RoleEntity>
  ) {}

  async addRole(roleDto: RoleDto) {
    const { roleName, description } = roleDto

    await this.roleRepository.save({ roleName, description })
  }
}
