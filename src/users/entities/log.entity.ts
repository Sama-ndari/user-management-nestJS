// src/log/log.schema.ts
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';

@Schema()
export class Log {
  @Prop({ required: true })
  action: string;

  @Prop({ required: true })
  actor: string;

  @Prop({ required: true })
  timestamp: string;

  @Prop({ type: MongooseSchema.Types.Mixed })
  target: any;

  @Prop({ type: MongooseSchema.Types.Mixed })
  details: any;
}

export type LogDocument = Log & Document;
export const LogSchema = SchemaFactory.createForClass(Log);