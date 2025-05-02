//src/users/entities/user.entity.ts
import { ApiProperty } from '@nestjs/swagger';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';



export enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  PENDING = 'pending',
}

@Schema({ timestamps: true })
export class User extends Document{
  @Prop({ type: String, required: false })
  @ApiProperty({ description: 'The unique identifier for the user in Keycloak', example: '123e4567-e89b-12d3-a456-426614174000' })
  keycloakId: string;

  @Prop({ type: String, required: true })
  @ApiProperty({ description: 'The username of the user', example: 'johndoe' })
  username: string;

  @Prop({ type: String, required: true })
  @ApiProperty({ description: 'The email address of the user', example: 'johndoe@example.com' })
  email: string;

  // @Prop({ type: String, required: true })
  // @ApiProperty({ description: 'The password of the user', example: 'P@ssw0rd' })
  // password: string;

  @Prop({ type: String, required: false })
  @ApiProperty({ description: 'The first name of the user', example: 'John', required: false })
  firstName?: string;

  @Prop({ type: String, required: false })
  @ApiProperty({ description: 'The last name of the user', example: 'Doe', required: false })
  lastName?: string;

  @Prop({ type: String, required: false })
  @ApiProperty({ description: 'The phone number of the user', example: '+1234567890', required: false })
  phone?: string;

  @Prop({ type: String, required: false })
  @ApiProperty({ description: 'The address of the user', example: '123 Main St, Springfield', required: false })
  address?: string;

  @Prop({ type: String, required: false })
  @ApiProperty({ description: 'The card number associated with the user', example: '4111111111111111', required: false })
  cardNumber?: string;

  @Prop({ type: String, required: false })
  @ApiProperty({ description: 'The logo or avatar of the user', example: 'https://example.com/logo.png', required: false })
  logo?: string;

  @Prop({ type: String, enum: UserStatus, required: false })
  @ApiProperty({ description: 'The status of the user', example: 'active', default: 'active', required: false })
  status?: UserStatus;

  // @Prop({ type: String, required: true })
  // @ApiProperty({ description: 'The role of the user', example: 'admin' })
  // role: string;
}

export type UserDocument = User & Document;

export const UserSchema = SchemaFactory.createForClass(User);