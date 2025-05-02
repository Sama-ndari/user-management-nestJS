import { Injectable, Scope, Inject } from '@nestjs/common';
import { REQUEST } from '@nestjs/core';
import * as winston from 'winston';
import { Log, LogDocument } from '../../users/entities/log.entity';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

@Injectable({ scope: Scope.REQUEST })
export class LoggerService {
  private logger: winston.Logger;

  constructor(
    @Inject(REQUEST) private readonly request: any,
    @InjectModel(Log.name) private logModel: Model<LogDocument>,
  ) {
    this.logger = winston.createLogger({
      level: 'info',
      // format: winston.format.json(),
      format: winston.format.printf(({ message }) => {
        // message is the logEntry object
        return JSON.stringify(message);
      }),
      transports: [
        new winston.transports.File({ filename: 'logs/audit.log' }),
      ],
    });
  }

  async logAction(action: string, target: any, details?: any) {
    const actor = this.request?.user?.username || 'system'; // Fallback to 'system' if no user
    console.log('actor', this.request?.user?.username);
    const logEntry = {
      action,                                   
      actor,                                    
      timestamp: new Date().toISOString(),     
      target,
      details, 
    };
    // await this.logModel.create(logEntry);
    this.logger.info(logEntry);
  }
}