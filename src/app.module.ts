import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { UsersModule } from './users/users.module';
import { VaultModule } from './vault/vault.module';

@Module({
  imports: [
    MongooseModule.forRoot(
      process.env.MONGODB_URI || 'mongodb+srv://samandari:samandari1@cluster0.zrfz0.mongodb.net/?retryWrites=true&w=majority&appName=ASYST-PAYALL-ECOMMERCE-LITE',
      ),
    UsersModule,
    VaultModule
  ],
  controllers: [],
  providers: [
  ],
})
export class AppModule { }
