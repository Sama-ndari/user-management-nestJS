//src/users/dto/login.dto.ts
import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({ example: 'johncena', description: 'Username or email of the user' })
  @IsString()
  @IsNotEmpty()
  identifier: string;

  @ApiProperty({ example: '123456', description: 'Password of the user' })
  @IsString()
  @IsNotEmpty()
  password: string;
}