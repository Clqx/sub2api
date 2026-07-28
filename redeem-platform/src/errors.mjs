export class AppError extends Error {
  constructor(status, code, message, details = undefined) {
    super(message)
    this.name = 'AppError'
    this.status = status
    this.code = code
    this.details = details
  }
}

export function asAppError(error) {
  if (error instanceof AppError) return error
  return new AppError(500, 'INTERNAL_ERROR', '服务器暂时无法处理请求')
}
