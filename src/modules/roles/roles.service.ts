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

  async getRoles() {
    await this.roleRepository.createQueryBuilder('role').getMany()
  }

  async getRoleById(id: string) {
    const role = await this.roleRepository.createQueryBuilder('role').where('role.id = :id', { id }).getOne()

    return role
  }
}
