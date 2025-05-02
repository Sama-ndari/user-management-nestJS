import { HttpException, HttpStatus, Injectable, NestMiddleware } from '@nestjs/common';
import axios, { AxiosError } from 'axios';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class XTokenMiddleware implements NestMiddleware {

  async use(req: Request, res: Response, next: NextFunction) {
    
    
    let apiKey = req.headers['x-api-key'];
    let authServer = process.env.AUTH_SERVER_URL;
    let realmName = process.env.REALM_NAME;

    try {
      const response = await axios.get(authServer + '/realms/' + realmName + '/check?apiKey=' + apiKey);
      console.log(response.status);
      next();
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const axiosError = error as AxiosError;
        if (axiosError.response?.status === 401) {
          // Handle the 401 error
          console.log("No authorized ");
          throw new HttpException('Unauthorized request', HttpStatus.UNAUTHORIZED);
        }
      }
      // Handle other errors
      
      throw new HttpException('Difficile de trouver le serveur', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
