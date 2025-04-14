import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { HttpModule } from '@nestjs/axios';
import { AuthGuard, KeycloakConnectModule, ResourceGuard, RoleGuard } from 'nest-keycloak-connect';
import { APP_GUARD } from '@nestjs/core';
import { UsersModule } from './users/users.module';
import { AppService } from './app.service';

@Module({
  imports: [
    // KeycloakConnectModule.register({
    //   authServerUrl: process.env.KEYCLOAK_AUTH_SERVER_URL || 'http://localhost:8080',
    //   realm: process.env.KEYCLOAK_REALM || 'nestjs-tuto',
    //   clientId: process.env.KEYCLOAK_CLIENT_ID || 'nestjs-app-admin',
    //   secret: process.env.KEYCLOAK_CLIENT_SECRET || 'NS979BlokWhRZSNIvIghwH7uZ1mb7tIb',
      // policyEnforcement: 'PERMISSIVE', // Allows unauthenticated access unless guarded
      // tokenValidation: 'ONLINE', // Validates tokens with Keycloak
    // }),
    MongooseModule.forRoot(
      process.env.MONGODB_URI || 'mongodb+srv://samandari:samandari1@cluster0.zrfz0.mongodb.net/?retryWrites=true&w=majority&appName=ASYST-PAYALL-ECOMMERCE-LITE',
      ),
    UsersModule
  ],
  controllers: [AppController],
  providers: [
    AppService,
    // { provide: APP_GUARD, useClass: AuthGuard }, // Ensures authentication
    // { provide: APP_GUARD, useClass: ResourceGuard }, // Protects resources
    // { provide: APP_GUARD, useClass: RoleGuard }, // Enforces role-based access
  ],
})
export class AppModule { }
