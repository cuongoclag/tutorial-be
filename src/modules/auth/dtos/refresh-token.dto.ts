export interface RefreshTokenDto {
  /**
   * User name to authenticate
   * @type {string}
   * @memberof RefreshToken
   */
  username: string
  /**
   * Refresh token for the user
   * @type {string}
   * @memberof RefreshToken
   */
  refreshToken: string
}
