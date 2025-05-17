import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { HttpException, HttpStatus } from '@nestjs/common';
import * as dotenv from 'dotenv';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { join } from 'path';
// import { MicroserviceOptions, Transport } from '@nestjs/microservices';

dotenv.config();
async function bootstrap() {
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
  console.log(`Application is running on: http://${process.env.IP_ADDRESS}:${process.env.PORT}/api`);
  console.log(`gRPC service is running on: localhost:5000`);
}
bootstrap();
