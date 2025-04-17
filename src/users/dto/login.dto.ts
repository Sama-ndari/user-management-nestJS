import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({ example: 'john_doe or john@example.com', description: 'Username or email of the user' })
  @IsString()
  @IsNotEmpty()
  identifier: string;

  @ApiProperty({ example: 'securePassword123', description: 'Password of the user' })
  @IsString()
  @IsNotEmpty()
  password: string;
}