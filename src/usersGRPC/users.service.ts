import { OnModuleInit, HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { CreateUserDto, UserRepresentation } from './dto/create-user.dto';
import axios from 'axios';
import { Client, ClientGrpc } from '@nestjs/microservices';
import { Transport } from '@nestjs/microservices';
import { join } from 'path';
import { Observable, lastValueFrom } from 'rxjs';
import * as dotenv from 'dotenv';
dotenv.config();

interface UserGrpcService {
  login(data: { username: string; password: string }): Observable<any>;
  logout(data: { refreshToken: string }): Observable<any>;
  createUser(data: any): Observable<any>;
  updateUser(data: { id: string; userDto: any }): Observable<any>;
  findUserById(data: { id: string }): Observable<UserRepresentation>;
  findUserByUsername(data: { username: string }): Observable<UserRepresentation>;
  findAllUsersByRole(data: { roleName: string }): Observable<UserRepresentation[]>;
  findAllUsers(data: {}): Observable<UserRepresentation[]>;
  findUserByEmail(data: { email: string }): Observable<UserRepresentation>;
  deleteUser(data: { id: string }): Observable<any>;
  assignRole(data: { userId: string; roleName: string }): Observable<any>;
  deAssignRole(data: { userId: string; roleName: string }): Observable<any>;
}

@Injectable()
export class UsersService implements OnModuleInit {
  @Client({
    transport: Transport.GRPC,
    options: {
      package: 'user',
      protoPath: join(__dirname, '../proto/user.proto'),
      url: '192.168.30.110:5000',
    },
  })
  private readonly client: ClientGrpc;
  
  private userService: UserGrpcService;

  onModuleInit() {
    this.userService = this.client.getService<UserGrpcService>('UserService');
  }


  async login(username: string, password: string): Promise<any> {
    return lastValueFrom(this.userService.login({ username, password }));
  }

  async logout(refreshToken: string): Promise<any> {
    return lastValueFrom(this.userService.logout({ refreshToken }));
  }

  async createUser(userDto: any): Promise<any> {
    return lastValueFrom(this.userService.createUser(userDto));
  }

  async updateUser(id: string, userDto: any) {
    return lastValueFrom(this.userService.updateUser({ id, userDto }));
  }

  async findUserById(id: string): Promise<UserRepresentation> {
    return lastValueFrom(this.userService.findUserById({ id }));
  }

  async findUserByUsername(username: string): Promise<UserRepresentation> {
    return lastValueFrom(this.userService.findUserByUsername({ username }));
  }

  async findAllUsersByRole(roleName: string): Promise<UserRepresentation[]> {
    return lastValueFrom(this.userService.findAllUsersByRole({ roleName }));
  }

  async findAllUsers(): Promise<UserRepresentation[]> {
    return lastValueFrom(this.userService.findAllUsers({}));
  }

  async findUserByEmail(email: string): Promise<UserRepresentation> {
    return lastValueFrom(this.userService.findUserByEmail({ email }));
  }

  async deleteUser(id: string) {
    return lastValueFrom(this.userService.deleteUser({ id }));
  }

  async assignRole(userId: string, roleName: string) {
    return lastValueFrom(this.userService.assignRole({ userId, roleName }));
  }

  async deAssignRole(userId: string, roleName: string) {
    return lastValueFrom(this.userService.deAssignRole({ userId, roleName }));
  }
}