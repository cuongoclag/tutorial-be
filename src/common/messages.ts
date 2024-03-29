import { HttpException } from '@nestjs/common'

// Error Messages
const INFO_MSG_USER_SUCCESS = (email) => `Add user successfully with email ${email}`

const INFO_MSG_USER_FAILED = (email) => `Add user fall with email ${email}`

const ERROR_MSG_NOT_AUTHORIZED = (email, target) => `user ${email} does not have permission for ${target}`

// HTTP Error Codes
const HTTP_ERROR_CODE_NOT_FOUND = 404
const HTTP_ERROR_CODE_BAD_REQUEST = 400
const HTTP_ERROR_CODE_SERVER_ERROR = 500
const HTTP_ERROR_CODE_FORBIDDEN = 403
const HTTP_ERROR_CODE_UNAUTHORIZED = 401
const HTTP_ERROR_CODE_METHOD_NOT_ALLOWED = 405
const HTTP_ERROR_CODE_NOT_IMPLEMENTED = 501

export const throwResourceException = (error) => {
  throw new HttpException(
    {
      status: error.statusCode,
      message: error.message
    },
    error.statusCode as number
  )
}

// messages for auth
const ERROR_MSG_AUTH_EXPIRED = (err) => `Token error: ${err}`

// MESSENGER
const PASSWORD_IS_WEEK =
  'Mật khẩu phải có ít nhất 12 ký tự và chứa ít nhất 1 số, 1 ký tự đặc biệt, 1 chữ hoa, 1 chữ thường'

const PASSWORD_CONFIRMPASSWORD_DIFFERENT = 'Mật khẩu không khớp Vui lòng nhập lại mật khẩu'

const EMAIL_INVALID = 'Email không hợp lệ'

const USERNAME_IS_ALREADY = 'tài khoản đã tồn tại'

const ERROR_MSG_AUTH_FORBIDDEN = `Cấm`

const WRONG_PASSWORD = 'Sai mật khẩu'

const TOKEN_INVALID = 'Token không hợp lệ'

const GET_ALL_USER_FAILED = 'Lấy thông tin toàn bộ thành viên thất bại'

const ROLE_INVALID = 'Bạn không có quyền truy cập'

const TOKEN_EXPIRES = 'Token hết hạn, vui lòng đăng nhập lại'

const USER_DO_NOT_EXIT = 'Email không tồn tại'

const ROLE_NOT_EXIT = 'Role không hợp lệ'
export class ErrorHandler extends Error {
  public message: string

  public description: string

  public httpCode: number

  public code: string

  constructor(message: string, description: string, httpCode: number) {
    super(message)
    Error.captureStackTrace(this, this.constructor)

    this.httpCode = httpCode || 500

    this.description = description || ''
    this.message = JSON.stringify({
      message: this.message,
      httpCode: this.httpCode,
      code: this.code,
      description: this.description
    })
  }
}

const makeError = (message: string) => (description?: any, httpCode?: number) =>
  new ErrorHandler(message, description, httpCode as number)

export default {
  // HTTP Error Codes
  HTTP_ERROR_CODE_BAD_REQUEST,
  EMAIL_INVALID,
  HTTP_ERROR_CODE_SERVER_ERROR,
  HTTP_ERROR_CODE_FORBIDDEN,
  HTTP_ERROR_CODE_UNAUTHORIZED,
  HTTP_ERROR_CODE_METHOD_NOT_ALLOWED,
  HTTP_ERROR_CODE_NOT_FOUND,
  HTTP_ERROR_CODE_NOT_IMPLEMENTED,
  PASSWORD_IS_WEEK,
  PASSWORD_CONFIRMPASSWORD_DIFFERENT,
  USERNAME_IS_ALREADY,
  ERROR_MSG_AUTH_FORBIDDEN,
  WRONG_PASSWORD,
  TOKEN_INVALID,
  GET_ALL_USER_FAILED,
  ROLE_INVALID,
  TOKEN_EXPIRES,
  USER_DO_NOT_EXIT,
  ROLE_NOT_EXIT,

  ResourceMakeError: makeError('io.scfpf.messages'),
  ResourceForbidden: makeError('Forbidden')
}
