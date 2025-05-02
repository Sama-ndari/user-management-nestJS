import { ExceptionFilter, Catch, ArgumentsHost, HttpException, BadRequestException } from '@nestjs/common';
import { Response } from 'express';
import { MongooseError } from 'mongoose';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
    catch(exception: unknown, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse<Response>();

        let status = 500;
        let message = 'Internal server error';


        if (exception instanceof HttpException) {                        
            status = exception.getStatus();
            message = exception.message;
        }

        if (exception instanceof Error) {
            status = 403;
            message = exception.message;
        }
        if(exception instanceof MongooseError){
            console.log({exception});
        }
        
        if (exception instanceof BadRequestException){                       
            return response.status(exception.getStatus()).json(exception.getResponse())
        }

        return response.status(status).json({
            statusCode: status,
            message,
            timestamp: new Date().toISOString(),
        });
    }
}