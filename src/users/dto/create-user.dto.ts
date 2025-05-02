//src/users/dto/create-user.dto.ts
import { IsString, IsEmail, IsNotEmpty, IsEnum, IsOptional, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUserDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty({ description: 'The username of the user', example: 'johndoe' })
  username: string;

  @IsEmail()
  @IsNotEmpty()
  @ApiProperty({ description: 'The email address of the user', example: 'johndoe@example.com' })
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(5)
  @ApiProperty({ description: 'The password of the user', example: 'P@ssw0rd' })
  password: string;

  @IsString()
  @IsOptional()
  @ApiProperty({ description: 'The first name of the user', example: 'Optional' })
  firstName?: string;

  @IsString()
  @IsOptional()
  @ApiProperty({ description: 'The last name of the user', example: 'Optional' })
  lastName?: string;

  @IsString()
  @IsOptional()
  @ApiProperty({ description: 'The phone number of the user', example: 'Optional', required: false })
  phone?: string;

  @IsString()
  @IsOptional()
  @ApiProperty({ description: 'The address of the user', example: 'Optional', required: false })
  address?: string;

  @IsString()
  @IsOptional()
  @ApiProperty({ description: 'The card number associated with the user', example: 'Optional', required: false })
  cardNumber?: string;

  @IsString()
  @IsOptional()
  @ApiProperty({ description: 'The logo or avatar of the user', example: 'Optional', required: false })
  logo?: string;

  @IsString()
  @IsOptional()
  @ApiProperty({ description: 'The status of the user', example: 'Optional', default: 'active', required: false })
  status?: 'active' | 'inactive' | 'pending';

  @ApiProperty({ description: 'The Group of the user', example: 'Admin' })
  group?: 'Admin' | 'Customer' | 'Merchant' | 'Commissionaire';
}
export class UserRepresentation {
  username: string;
  email: string;
  firstName?: string;
  lastName?: string;
  credentials: Credential[];
  enabled: boolean;
  emailVerified: boolean;
  attributes?: {
    phone?: string;
    address?: string;
    cardNumber?: string;
    logo?: string;
    status?: 'active' | 'inactive' | 'pending';
    group?: 'Admin' | 'Customer' | 'Merchant' | 'Commissionaire';
  };
}
export class Credential {
  type: string;
  value: string;
  temporary: boolean;
}

export class RoleRepresentation{
  id:string;
  name:string;
  description:string;
  composite:string;
  clientRole:string;
  containerId:string
}

export class CreateUserDatabaseDto {
  @IsString()
  @IsOptional()
  @ApiProperty({ description: 'The unique identifier for the user in Keycloak', example: '123e4567-e89b-12d3-a456-426614174000' })
  keycloakId: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({ description: 'The username of the user', example: 'johndoe' })
  username: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({ description: 'The email address of the user', example: 'johndoe@example.com' })
  email: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({ description: 'The password of the user', example: 'P@ssw0rd' })
  password: string;

  @IsString()
  @IsOptional()
  @ApiProperty({ description: 'The first name of the user', example: 'John' })
  firstName?: string;

  @IsString()
  @IsOptional()
  @ApiProperty({ description: 'The last name of the user', example: 'Doe' })
  lastName?: string;

  @IsString()
  @IsOptional()
  @ApiProperty({ description: 'The phone number of the user', example: '+1234567890', required: false })
  phone?: string;

  @IsString()
  @IsOptional()
  @ApiProperty({ description: 'The address of the user', example: '123 Main St, Springfield', required: false })
  address?: string;

  @IsString()
  @IsOptional()
  @ApiProperty({ description: 'The card number associated with the user', example: '4111111111111111', required: false })
  cardNumber?: string;

  @IsString()
  @IsOptional()
  @ApiProperty({ description: 'The logo or avatar of the user', example: 'https://example.com/logo.png', required: false })
  logo?: string;

  @ApiProperty({ description: 'The status of the user', example: 'active', default: 'active', required: false })
  status?: 'active' | 'inactive' | 'pending';

}

export class LoginUserDto{
  @IsString()
  @IsNotEmpty()
  username: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}

export class ResetPasswordDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty({ description: 'The password of the user', example: 'Password123$' })
  newPassword: string;
}