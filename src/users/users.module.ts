import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { KeycloakService } from 'src/keycloak/keycloak.service';
import { HttpModule, HttpService } from '@nestjs/axios';
import { DatabaseService } from 'src/database/database.service';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './entities/user.entity';
import { TransactionsService } from 'src/transactions/transactions.service';

@Module({
  imports: [HttpModule,
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
  ],
  providers: [UsersService, KeycloakService, DatabaseService, TransactionsService],
  controllers: [UsersController],
  exports: [UsersService],
})
export class UsersModule {}