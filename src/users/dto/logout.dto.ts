import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';


export class LogoutDto {
  @ApiProperty({ example: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaffffffffffffffffffffffffffff' })
  @IsString()
  @IsNotEmpty()
  refreshToken: string;
}