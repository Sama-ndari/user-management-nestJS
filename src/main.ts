import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { HttpException, HttpStatus } from '@nestjs/common';
import * as dotenv from 'dotenv';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { join } from 'path';
import * as Vault from 'node-vault';
dotenv.config();

// Global configuration class to store Vault secrets
export class Config {
  static app: {
    PORT: string;
    IP_ADDRESS: string;
    SERVER_API: string;
    BEARER_TOKEN: string;
  };
  static redis: {
    REDIS_HOST: string;
    REDIS_PORT: string;
  };
  static database: {
    DATABASE_HOST: string;
    DATABASE_PORT: string;
    DATABASE_NAME: string;
  };
  static keycloak: {
    KEYCLOAK_LOGIN_URL: string;
    KEYCLOAK_LOGOUT_URL: string;
    KEYCLOAK_AUTH_SERVER_URL: string;
    KEYCLOAK_REALM: string;
    KEYCLOAK_CLIENT_ID: string;
    KEYCLOAK_CLIENT_SECRET: string;
    KEYCLOAK_ADMIN_ID: string;
    KEYCLOAK_ADMIN_SECRET: string;
    KEYCLOAK_ADMIN_BASE_URL: string;
    KEYCLOAK_ADMIN_LINK_LIFESPAN: string;
    KEYCLOAK_ADMIN_REDIRECT_URL: string;
  };
  static mail: {
    SMTP_SERVICE: string;
    SMTP_HOST: string;
    SMTP_PORT: string;
    SMTP_SECURE: boolean;
    SMTP_USER: string;
    SMTP_PASS: string;
    EMAIL_FROM_NAME: string;
    EMAIL_FROM_ADDRESS: string;
    LOGIN_URL: string;
  };
}

async function initializeVaultSecrets(): Promise<void> {
  // Validate environment variables
  const vaultAddr = process.env.VAULT_ADDR;
  const vaultToken = process.env.VAULT_TOKEN;
  if (!vaultAddr || !vaultToken) {
    throw new Error('VAULT_ADDR and VAULT_TOKEN environment variables are required');
  }

  // Create standalone Vault client
  const vault = Vault({
    apiVersion: 'v1',
    endpoint: vaultAddr,
    token: vaultToken,
  });

  try {
    // Verify Vault connectivity
    await vault.health();
    console.log('Vault connection established');

    // Fetch all secrets
    const [appConfig, redisConfig, databaseConfig, keycloakConfig, mailConfig] = await Promise.all([
      vault.read('user-management/data/config-app').then((res) => res.data.data),
      vault.read('user-management/data/config-redis').then((res) => res.data.data),
      vault.read('user-management/data/config-database').then((res) => res.data.data),
      vault.read('user-management/data/config-keycloak').then((res) => res.data.data),
      vault.read('user-management/data/config-mail').then((res) => res.data.data),
      // vault.read('user-management/data/config-firebase').then((res) => res.data.data),
    ]);

    // Populate Config
    Config.app = {
      PORT: appConfig.PORT,
      IP_ADDRESS: appConfig.IP_ADDRESS,
      SERVER_API: appConfig.SERVER_API,
      BEARER_TOKEN: appConfig.BEARER_TOKEN,
    };
    Config.redis = {
      REDIS_HOST: redisConfig.REDIS_HOST,
      REDIS_PORT: redisConfig.REDIS_PORT,
    };
    Config.database = {
      DATABASE_HOST: databaseConfig.DATABASE_HOST,
      DATABASE_PORT: databaseConfig.DATABASE_PORT,
      DATABASE_NAME: databaseConfig.DATABASE_NAME,
    };
    Config.keycloak = {
      KEYCLOAK_LOGIN_URL: keycloakConfig.KEYCLOAK_LOGIN_URL,
      KEYCLOAK_LOGOUT_URL: keycloakConfig.KEYCLOAK_LOGOUT_URL,
      KEYCLOAK_AUTH_SERVER_URL: keycloakConfig.KEYCLOAK_AUTH_SERVER_URL,
      KEYCLOAK_REALM: keycloakConfig.KEYCLOAK_REALM,
      KEYCLOAK_CLIENT_ID: keycloakConfig.KEYCLOAK_CLIENT_ID,
      KEYCLOAK_CLIENT_SECRET: keycloakConfig.KEYCLOAK_CLIENT_SECRET,
      KEYCLOAK_ADMIN_ID: keycloakConfig.KEYCLOAK_ADMIN_ID,
      KEYCLOAK_ADMIN_SECRET: keycloakConfig.KEYCLOAK_ADMIN_SECRET,
      KEYCLOAK_ADMIN_BASE_URL: keycloakConfig.KEYCLOAK_ADMIN_BASE_URL,
      KEYCLOAK_ADMIN_LINK_LIFESPAN: keycloakConfig.KEYCLOAK_ADMIN_LINK_LIFESPAN,
      KEYCLOAK_ADMIN_REDIRECT_URL: keycloakConfig.KEYCLOAK_ADMIN_REDIRECT_URL,
    };
    Config.mail = {
      SMTP_SERVICE: mailConfig.SMTP_SERVICE,
      SMTP_HOST: mailConfig.SMTP_HOST,
      SMTP_PORT: mailConfig.SMTP_PORT,
      SMTP_SECURE: mailConfig.SMTP_SECURE === 'true',
      SMTP_USER: mailConfig.SMTP_USER,
      SMTP_PASS: mailConfig.SMTP_PASS,
      EMAIL_FROM_NAME: mailConfig.EMAIL_FROM_NAME,
      EMAIL_FROM_ADDRESS: mailConfig.EMAIL_FROM_ADDRESS,
      LOGIN_URL: mailConfig.LOGIN_URL,
    };

    console.log('Vault secrets loaded:', {
      app: Config.app,
      redis: Config.redis,
      database: { ...Config.database, DATABASE_PASSWORD: '****' },
      keycloak: { ...Config.keycloak, KEYCLOAK_CLIENT_SECRET: '****', KEYCLOAK_ADMIN_SECRET: '****' },
      mail: { ...Config.mail, SMTP_PASS: '****' },
      // firebase: { ...Config.firebase, private_key: '****' },
    });
  } catch (error) {
    console.error('Failed to initialize Vault secrets:', error.message);
    throw new Error('Application initialization failed');
  }
}


async function bootstrap() {

  // Initialize Vault secrets
  await initializeVaultSecrets();

  const app = await NestFactory.create(AppModule);

  // Add global error filter
  app.useGlobalFilters({
    catch(exception: any, host: any) {
      if (exception.response?.status === 405) {
        throw new HttpException('Method not allowed for this endpoint', HttpStatus.METHOD_NOT_ALLOWED);
      }
      throw exception;
    }
  });

  const config = new DocumentBuilder()
    .setTitle('NestJs UserManagement Keycloak ')
    .setDescription('The keycloak API integration with NestJS')
    .setVersion('1.0')
    .addBearerAuth()
    .addTag('Audit & System')
    .addTag('User Management')
    .addTag('Authentication')
    .addTag('Roles Management')
    .addTag('Group Management')
    .addTag('Client Roles')
    .addTag('Client Management')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);
  // Create gRPC microservice
  app.connectMicroservice<MicroserviceOptions>({
    transport: Transport.GRPC,
    options: {
      package: 'user',
      protoPath: join(__dirname, 'proto/user.proto'),
      url: '0.0.0.0:5000',
    },
  });

  // // Start all services
  await app.startAllMicroservices();
  await app.listen(process.env.PORT || 3000);
  console.log(`Application is running on: http://${Config.app.IP_ADDRESS || process.env.IP_ADDRESS}:${Config.app.PORT || process.env.PORT}/api`);
  console.log(`gRPC service is running on: localhost:5000`);
}
bootstrap();
