import { Injectable } from '@nestjs/common';

@Injectable()
export class ResponseService {
    responseSuccess(data: any): any {
        const response = {
            statusCode: 200,
            message: 'success',
            data: data ? data : null,
            

        };
        return response;
    }

    responseError(error: string): any {
        const response = {
          statusCode: 400,
          message: error,
        };
        return response;
    }

    responseInternalError(error: string): any {
        const response = {
            message: error,
        };
        return response;
    }
}
