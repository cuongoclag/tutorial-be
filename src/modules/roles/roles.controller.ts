import { Body, Controller, Get, Post } from '@nestjs/common'
import { RoleDto } from './dtos/role.dto'
import { RolesService } from './roles.service'
import { ApiBody, ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger'

@Controller('roles')
@ApiTags('Role')
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

  @Get('getRoles')
  @ApiOperation({ summary: 'Get role' })
  async getRoles() {
    return this.rolesService.getRoles()
  }
}
