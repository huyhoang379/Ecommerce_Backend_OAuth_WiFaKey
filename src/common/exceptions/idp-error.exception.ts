import { HttpException, HttpStatus } from '@nestjs/common';

export class IdpErrorException extends HttpException {
  constructor(
    public readonly errorCode: string,
    public readonly errorDescription: string,
    public readonly idpStatusCode?: number,
  ) {
    super(
      {
        statusCode: IdpErrorException.mapIdpStatusCode(idpStatusCode),
        message: errorDescription,
        error: errorCode,
        idpError: true,
      },
      IdpErrorException.mapIdpStatusCode(idpStatusCode),
    );
  }

  private static mapIdpStatusCode(idpStatusCode?: number): HttpStatus {
    switch (idpStatusCode) {
      case 400:
        return HttpStatus.BAD_REQUEST;
      case 401:
        return HttpStatus.UNAUTHORIZED;
      case 403:
        return HttpStatus.FORBIDDEN;
      case 404:
        return HttpStatus.NOT_FOUND;
      case 500:
        return HttpStatus.INTERNAL_SERVER_ERROR;
      default:
        return HttpStatus.UNAUTHORIZED;
    }
  }
}
