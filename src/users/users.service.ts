//src/users/users.service.ts
import { Delete, HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { KeycloakService } from '../keycloak/keycloak.service';
import { CreateUserDto, UserRepresentation } from './dto/create-user.dto';
import { DatabaseService } from '../database/database.service';
import { TransactionsService } from '../transactions/transactions.service';
import axios from 'axios';
import * as dotenv from 'dotenv';
import { LoginDto } from './dto/login.dto';
import { PageDto } from 'src/common/page-dto';
import { PageOptionsDto } from 'src/common/page-options-dto';
dotenv.config();

@Injectable()
export class UsersService {
  constructor(
    private transactionsService: TransactionsService,
  ) { }


  async login(userdto : LoginDto): Promise<any> {
    return this.transactionsService.login(userdto);
  }

  async decodeToken(token: string): Promise<any> {
    const decodedData = await this.transactionsService.decodeToken(token);
    return decodedData;
  }

  async refreshAccessToken(refreshToken: string): Promise<any> {
    return this.transactionsService.refreshAccessToken(refreshToken);
  }

  async logout(refreshToken: string): Promise<any> {
    return this.transactionsService.logout(refreshToken);
  }


  async createUser(userDto: any): Promise<any> {
    const createdUser = await this.transactionsService.createUser(userDto);
    return createdUser;
  }

  async updateUser(id: string, userDto: any) {
    const updatedUser = await this.transactionsService.updateUser(id, userDto);
    return updatedUser;
  }

  async resetPassword(id: string, newPassword: string): Promise<any> {
    return this.transactionsService.resetPassword(id, newPassword);
  }

  async findUserById(id: string): Promise<UserRepresentation> {
    return this.transactionsService.findUserById(id);
  }

  async findUserByUsername(username: string): Promise<UserRepresentation> {
    return this.transactionsService.findUserByUsername(username);
  }

  async getConnectedUsers(): Promise<any[]> {
    return this.transactionsService.getConnectedUsers();
}

  async findAllUsersByRole(roleName: string): Promise<UserRepresentation[]> {
    return this.transactionsService.findAllUsersByRole(roleName);
  }

  async findAllUsers(pageOptionsDto?): Promise<PageDto<any>> {
    return this.transactionsService.findAllUsers(pageOptionsDto);
  }

  async findUserByEmail(email: string): Promise<UserRepresentation> {
    return this.transactionsService.findUserByEmail(email);
  }

  async deleteUser(id: string) {
    const deletedUser = await this.transactionsService.deleteUser(id);
    return await { message: 'User deleted successfully', DeletedUser: deletedUser };
  }

  async createRole(roleName: string, description: string): Promise<any> {
    return this.transactionsService.createRole(roleName, description);
  }

  async deleteRole(roleName: string): Promise<any> {
    return this.transactionsService.deleteRole(roleName);
  }

  async updateRole(roleName: string, newName?: string, newDescription?: string): Promise<any> {
    return this.transactionsService.updateRole(roleName, newName, newDescription);
  }

  async assignRole(userId: string, roleName: string) {
    await this.transactionsService.assignRole(userId, roleName);
    return { message: 'Role assigned successfully' };
  }

  async deAssignRole(userId: string, roleName: string) {
    await this.transactionsService.deAssignRole(userId, roleName);
    return { message: 'Role deAssigned successfully' };
  }
}