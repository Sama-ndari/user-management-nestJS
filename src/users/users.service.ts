//src/users/users.service.ts
import { Injectable } from '@nestjs/common';
import { UserRepresentation } from './dto/create-user.dto';
import { TransactionsService } from '../transactions/transactions.service';
import * as dotenv from 'dotenv';
import { LoginDto } from './dto/login.dto';
import { PageDto } from 'src/common/page-dto/page-dto';
dotenv.config();

@Injectable()
export class UsersService {
  constructor(
    private transactionsService: TransactionsService,
  ) { }

  async getAllActions(): Promise<string[]> {
    return this.transactionsService.getAllActions();
  }

  async getAuditLogs(Object: any): Promise<string[]> {
    return this.transactionsService.getAuditLogs(Object);
  }

  async deleteAuditLogs(Object: any): Promise<{ deletedCount: number }>{
    return this.transactionsService.deleteAuditLogs(Object);
  }



  // *** USER ***



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

  async createUserWithoutRoles(userDto: any): Promise<any> {
    const createdUser = await this.transactionsService.createUserWithoutRoles(userDto);
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

  async findAllUsers(pageOptionsDto?): Promise<PageDto<any>> {
    return await this.transactionsService.findAllUsers(pageOptionsDto);
  }

  async findUserByEmail(email: string): Promise<UserRepresentation> {
    return this.transactionsService.findUserByEmail(email);
  }

  async deleteUser(id: string) {
    const deletedUser = await this.transactionsService.deleteUser(id);
    return await { message: 'User deleted successfully', DeletedUser: deletedUser };
  }



  // *** REALM ROLES ***



  async createRealmRole(roleName: string, description: string): Promise<any> {
    return this.transactionsService.createRealmRole(roleName, description);
  }

  async deleteRealmRole(roleName: string): Promise<any> {
    return this.transactionsService.deleteRealmRole(roleName);
  }

  async updateRealmRole(roleName: string, newName?: string, newDescription?: string): Promise<any> {
    return this.transactionsService.updateRealmRole(roleName, newName, newDescription);
  }

  async assignRealmRole(userId: string, roleName: string) {
    await this.transactionsService.assignRealmRole(userId, roleName);
    return { message: 'Role assigned successfully' };
  }

  async deAssignRealmRole(userId: string, roleName: string) {
    await this.transactionsService.deAssignRealmRole(userId, roleName);
    return { message: 'Role deAssigned successfully' };
  }

  async getAllRealmRoles(): Promise<any[]> {
    return this.transactionsService.getAllRealmRoles();
  }

  async getUserRealmRoles(userId: string): Promise<any[]> {
    return this.transactionsService.getUserRealmRoles(userId);
  }

  async findAllUsersByRealmRole(roleName: string): Promise<UserRepresentation[]> {
    return this.transactionsService.findAllUsersByRealmRole(roleName);
  }


  // *** GROUPS ***



  async createGroup(groupName: string, attributes?: Record<string, any>): Promise<any> {
    return this.transactionsService.createGroup(groupName, attributes);
  }

  async updateGroup(groupId: string, groupName?: string, attributes?: Record<string, any>): Promise<any> {
    return this.transactionsService.updateGroup(groupId, groupName, attributes);
  }

  async deleteGroup(groupId: string): Promise<any> {
    return this.transactionsService.deleteGroup(groupId);
  }

  async getAllGroups(): Promise<any[]> {
    return this.transactionsService.getAllGroups();
  }

  async addRoleToGroup(groupId: string, roleName: string): Promise<any> {
    return this.transactionsService.addRoleToGroup(groupId, roleName);
  }

  async removeRoleFromGroup(groupId: string, roleName: string): Promise<any> {
    return this.transactionsService.removeRoleFromGroup(groupId, roleName);
  }

  async getGroupRoles(groupId: string): Promise<any> {
    return this.transactionsService.getGroupRoles(groupId);
  }

  async addUserToGroup(userId: string, groupId: string): Promise<void> {
    await this.transactionsService.addUserToGroup(userId, groupId);
  }

  async removeUserFromGroup(userId: string, groupId: string): Promise<void> {
    await this.transactionsService.removeUserFromGroup(userId, groupId);
  }

  async getAllUsersFromGroup(groupId: string): Promise<any[]> {
    return this.transactionsService.getAllUsersFromGroup(groupId);
  }

  async getGroupById(groupId: string): Promise<any> {
    return this.transactionsService.getGroupById(groupId);
  }

  async getGroupByName(groupName: string): Promise<any> {
    return this.transactionsService.getGroupByName(groupName);
  }

  async getUserGroups(userId: string): Promise<any[]> {
    return this.transactionsService.getUserGroups(userId);
  }



  // *** CLIENT ROLES ***



  async createClientRole(roleName: string, description: string): Promise<void> {
    return this.transactionsService.createClientRole(roleName, description);
  }

  async updateClientRole(roleName: string, newName?: string, newDescription?: string): Promise<void> {
    return this.transactionsService.updateClientRole(roleName, newName, newDescription);
  }

  async getAllClientRoles(): Promise<any[]> {
    return this.transactionsService.getAllClientRoles();
  }

  async deleteClientRole(roleName: string): Promise<void> {
    return this.transactionsService.deleteClientRole(roleName);
  }

  async addClientRoleToGroup(groupId: string, roleName: string): Promise<void> {
    return this.transactionsService.addClientRoleToGroup(groupId, roleName);
  }

  async removeClientRoleFromGroup(groupId: string, roleName: string): Promise<void> {
    return this.transactionsService.removeClientRoleFromGroup(groupId, roleName);
  }

  async addClientRoleToUser(userId: string, roleName: string): Promise<void> {
    return this.transactionsService.addClientRoleToUser(userId, roleName);
  }

  async removeClientRoleFromUser(userId: string, roleName: string): Promise<void> {
    return this.transactionsService.removeClientRoleFromUser(userId, roleName);
  }

  async findUsersByClientRole(roleName: string): Promise<any[]> {
    return this.transactionsService.findUsersByClientRole(roleName);
  }

  async findClientRolesByUserId(userId: string): Promise<any[]> {
    return this.transactionsService.findClientRolesByUserId(userId);
  }
  
  // *** CLIENTS ***

  async createClient(clientData: any): Promise<any> {
    return this.transactionsService.createClient(clientData);
  }

  async deleteClient(clientId: string): Promise<void> {
    return this.transactionsService.deleteClient(clientId);
  }

  async updateClient(clientId: string, clientData: any): Promise<any> {
    return this.transactionsService.updateClient(clientId, clientData);
  }

  async getClientByName(clientName: string): Promise<any> {
    return this.transactionsService.getClientByName(clientName);
  }

  async getClientById(clientId: string): Promise<any> {
    return this.transactionsService.getClientById(clientId);
  }

  async getAllClients(): Promise<any[]> {
    return this.transactionsService.getAllClients();
  }

  async addClientRole(clientId: string, roleName: string, description: string): Promise<void> {
    return this.transactionsService.addClientRole(clientId, roleName, description);
  }

  async removeClientRole(clientId: string, roleName: string): Promise<void> {
    return this.transactionsService.removeClientRole(clientId, roleName);
  }

  async regenerateClientSecret(clientId: string): Promise<any> {
    return this.transactionsService.regenerateClientSecret(clientId);
  }
}