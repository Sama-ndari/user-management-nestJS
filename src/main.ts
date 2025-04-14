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
    .addBearerAuth()
    .setTitle('NestJs keycloak ')
    .setDescription('The keycloak API integration')
    .setVersion('1.0')
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
  console.log(`Application is running on: ${await app.getUrl()}`);  
  console.log(`gRPC service is running on: localhost:5000`);
}
bootstrap();
