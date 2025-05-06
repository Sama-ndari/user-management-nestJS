import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { KeycloakService } from 'src/keycloak/keycloak.service';
import { HttpModule, HttpService } from '@nestjs/axios';
import { DatabaseService } from 'src/database/database.service';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './entities/user.entity';
import { TransactionsService } from 'src/transactions/transactions.service';
import { ClientService } from 'src/keycloak/managements/clientManagement.service';
import { ClientRoleService } from 'src/keycloak/managements/clientRoleManagement.service';
import { GroupService } from 'src/keycloak/managements/groupManagement.service';
import { RealmRoleService } from 'src/keycloak/managements/realmRoleManagement.service';
import { UserKeycloakService } from 'src/keycloak/managements/userManagement.service';
import { JwtStrategy } from 'src/keycloak/security/jwtStrategy.service';
import { LoggerService } from 'src/keycloak/security/logger.service';
import { Log, LogSchema } from './entities/log.entity';
import { EmailService } from 'src/mail/mail.service';
import { PassportModule } from '@nestjs/passport';

@Module({
  imports: [HttpModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    MongooseModule.forFeature([{ name: Log.name, schema: LogSchema }]),
  ],
  providers: [
    UsersService, KeycloakService, DatabaseService, TransactionsService,
    LoggerService, JwtStrategy, ClientRoleService, RealmRoleService,
    UserKeycloakService, GroupService,ClientService,EmailService
  ],
  controllers: [UsersController],
  exports: [UsersService],
})
export class UsersModule {}