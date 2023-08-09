import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException
} from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { Request } from 'express'
import { AuthService } from './../modules/auth/auth.service'
import { UserRole } from '../common/common.enum'
import messages from '../common/messages'

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private authService: AuthService, private jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>()
    const token = this.extractTokenFromHeader(request)

    if (!token) {
      throw new UnauthorizedException()
    }

    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: 'topSecret51'
      })

      const { id } = payload
      const user = await this.authService.getUserById(id)

      if (!user) {
        throw new UnauthorizedException()
      }

      request.user = user // Attach the user to the request

      // Optionally check for user role
      if (user.role_role_name !== UserRole.ADMIN) {
        throw new HttpException(
          messages.ResourceForbidden(messages.ROLE_INVALID, messages.HTTP_ERROR_CODE_UNAUTHORIZED),
          HttpStatus.UNAUTHORIZED
        )
      }
    } catch (error) {
      throw new HttpException(
        messages.ResourceForbidden(messages.TOKEN_EXPIRES, messages.HTTP_ERROR_CODE_UNAUTHORIZED),
        HttpStatus.UNAUTHORIZED
      )
    }

    return true
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const authorizationHeader = request.headers.authorization
    if (!authorizationHeader) {
      return undefined
    }

    const [type, token] = authorizationHeader.split(' ')
    if (type === 'Bearer') {
      return token
    }

    return undefined
  }
}
