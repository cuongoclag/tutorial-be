import { Body, Controller, Post } from '@nestjs/common'
import { RoleDto } from './dtos/role.dto'
import { RolesService } from './roles.service'
import { ApiBody, ApiOkResponse, ApiOperation } from '@nestjs/swagger'

@Controller('roles')
export class RolesController {
  constructor(private rolesService: RolesService) {}

  @Post('role')
  @ApiOperation({ summary: 'Roles' })
  @ApiBody({
    type: RoleDto
  })
  @ApiOkResponse({
    type: RoleDto,
    description: 'Add a new role success'
  })
  async signIn(@Body() roleDto: RoleDto) {
    return this.rolesService.addRole(roleDto)
  }
}
