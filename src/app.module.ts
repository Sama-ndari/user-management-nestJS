import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { HttpModule } from '@nestjs/axios';
import { AuthGuard, KeycloakConnectModule, ResourceGuard, RoleGuard } from 'nest-keycloak-connect';
import { APP_GUARD } from '@nestjs/core';
import { UsersModule } from './users/users.module';

@Module({
  imports: [
    MongooseModule.forRoot(
      process.env.MONGODB_URI || 'mongodb+srv://samandari:samandari1@cluster0.zrfz0.mongodb.net/?retryWrites=true&w=majority&appName=ASYST-PAYALL-ECOMMERCE-LITE',
      ),
    UsersModule
  ],
  controllers: [],
  providers: [
    // AppService,
    // { provide: APP_GUARD, useClass: AuthGuard }, // Ensures authentication
    // { provide: APP_GUARD, useClass: ResourceGuard }, // Protects resources
    // { provide: APP_GUARD, useClass: RoleGuard }, // Enforces role-based access
  ],
})
export class AppModule { }
