//src/users/keycloak/keycloak.service.ts
import { forwardRef, HttpException, HttpStatus, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { HttpService } from "@nestjs/axios";
import { firstValueFrom, lastValueFrom } from "rxjs";
import { CreateUserDatabaseDto, RoleRepresentation, UserRepresentation } from 'src/users/dto/create-user.dto';
import { LoginDto } from 'src/users/dto/login.dto';
import * as path from 'path';
import * as fs from 'fs';
import { ClientRoleService } from './managements/clientRoleManagement.service';
import { RealmRoleService } from './managements/realmRoleManagement.service';
import { UserKeycloakService } from './managements/userManagement.service';
import { GroupService } from './managements/groupManagement.service';
import { ClientService } from './managements/clientManagement.service';
import { Log, LogDocument } from '../users/entities/log.entity';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

@Injectable()
export class KeycloakService {

  constructor(private readonly httpService: HttpService,
    @Inject(forwardRef(() => ClientRoleService)) private readonly clientRoleService: ClientRoleService,
    @Inject(forwardRef(() => RealmRoleService)) private readonly realmRoleService: RealmRoleService,
    @Inject(forwardRef(() => UserKeycloakService)) private readonly userKeycloakService: UserKeycloakService,
    @Inject(forwardRef(() => GroupService)) private readonly groupService: GroupService,
    @Inject(forwardRef(() => ClientService)) private readonly clientService: ClientService,
    @InjectModel(Log.name) private logModel: Model<LogDocument>,
  ) { }




  // ==============================
  // Helpers
  // ==============================



  public async getKeycloakPublicKey(): Promise<string> {
    console.log('Fetching Keycloak public key...');
    const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/realms/Waangu-Marketplace/protocol/openid-connect/certs`;
    const response = await firstValueFrom(this.httpService.get(url));
    const cert = response.data.keys[0].x5c[0];
    console.log('Keycloak public key:', cert);
    return `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----`;
  }

  async getAuditLogs(filters: {
    date?: string;
    actor?: string;
    action?: string;
    startTime?: string; // format: 'HH:mm'
    endTime?: string;   // format: 'HH:mm'
  }) {
    const logFilePath = path.join(__dirname, '..', '..', '..', 'logs', 'audit.log');
    if (!fs.existsSync(logFilePath)) return null;
    const data = fs.readFileSync(logFilePath, 'utf-8');
    const logs = data
      .split('\n')
      .filter(line => line.trim() !== '')
      .map(line => {
        try {
          return JSON.parse(line);
        } catch {
          return { raw: line };
        }
      });

    // Filtering
    return logs.filter(entry => {
      if (!entry.actor && !entry.action && !entry.timestamp) return false;
      let match = true;
      if (filters.actor) match = match && entry.actor === filters.actor;
      if (filters.action) match = match && entry.action === filters.action;
      if (filters.date && entry.timestamp) {
        match = match && entry.timestamp.startsWith(filters.date);
      }
      // Time interval filtering
      if (filters.startTime && filters.endTime && entry.timestamp) {
        // Extract time part from timestamp
        const time = entry.timestamp.substring(11, 16); // 'HH:mm'
        match = match && (time >= filters.startTime && time <= filters.endTime);
      }
      return match;
    });
  }

  async deleteAuditLogs(filters: {
    date?: string;
    actor?: string;
    action?: string;
    startTime?: string;
    endTime?: string;
  }): Promise<{ deletedCount: number }> {
    let query: any = {};

    // Apply filters if provided; otherwise, delete all logs
    if (filters.actor) query.actor = filters.actor;
    if (filters.action) query.action = filters.action;
    if (filters.date) query.timestamp = { $regex: `^${filters.date}`, $options: 'i' };
    if (filters.startTime && filters.endTime) {
      query.timestamp = {
        $gte: `${filters.date || new Date().toISOString().split('T')[0]}T${filters.startTime}:00.000Z`,
        $lte: `${filters.date || new Date().toISOString().split('T')[0]}T${filters.endTime}:59.999Z`,
      };
    }

    try {
      const result = await this.logModel.deleteMany(query).exec();
      if (result.deletedCount === 0) {
        return { deletedCount: 0};
      }
      return { deletedCount: result.deletedCount };
    } catch (error) {
      throw new Error(`Failed to delete logs: ${error.message}`);
    }
  }

  async getAuditLogs2(filters: {
    date?: string;
    actor?: string;
    action?: string;
    startTime?: string; // format: 'HH:mm'
    endTime?: string; // format: 'HH:mm'
  }): Promise<any[]> {
    let query: any = {};

    if (filters.actor) query.actor = filters.actor;
    if (filters.action) query.action = filters.action;
    if (filters.date) query.timestamp = { $regex: `^${filters.date}`, $options: 'i' };
    if (filters.startTime && filters.endTime) {
      query.timestamp = {
        $gte: `${filters.date || new Date().toISOString().split('T')[0]}T${filters.startTime}:00.000Z`,
        $lte: `${filters.date || new Date().toISOString().split('T')[0]}T${filters.endTime}:59.999Z`,
      };
    }

    try {
      const logs = await this.logModel.find(query).exec();
      return logs.map(log => ({
        action: log.action,
        actor: log.actor,
        timestamp: log.timestamp,
        target: log.target,
        details: log.details,
      }));
    } catch (error) {
      console.error('Error fetching logs:', error);
      return [];
    }
  }

  public async getClientUuid(token?: string): Promise<string> {
    if (!token) token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/clients?clientId=${process.env.KEYCLOAK_CLIENT_ID}`;
    const response = await firstValueFrom(
      this.httpService.get(url, {
        headers: { Authorization: `Bearer ${token}` },
      }),
    );
    const clients = response.data;
    if (!clients.length) {
      throw new HttpException(`Client "${process.env.KEYCLOAK_CLIENT_ID}" not found`, HttpStatus.NOT_FOUND);
    }
    return clients[0].id;
  }

  public async getAdminToken(): Promise<string> {
    const url = process.env.KEYCLOAK_LOGIN_URL || '';

    const formData = new URLSearchParams();
    formData.append('client_id', process.env.KEYCLOAK_CLIENT_ID || '');
    formData.append('client_secret', process.env.KEYCLOAK_CLIENT_SECRET || '');
    formData.append('grant_type', 'client_credentials');
    try {
      const response = await firstValueFrom(
        this.httpService.post(url, formData.toString(), {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }),
      );
      const { access_token } = response.data;
      return access_token;
    } catch (error) {
      throw new HttpException(`Admin token fetch failed: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }



  // ==============================
  // User Management Endpoints
  // ==============================



  async login(userdto: LoginDto): Promise<any> {
    return this.userKeycloakService.login(userdto);
  }

  public async decodeJwt(token: string): Promise<any> {
    return this.userKeycloakService.decodeJwt(token);
  }

  async refreshAccessToken(refreshToken: string): Promise<{ access: string }> {
    return this.userKeycloakService.refreshAccessToken(refreshToken);
  }

  async logout(refreshToken: string): Promise<void> {
    return this.userKeycloakService.logout(refreshToken);
  }

  async createUser(user: any): Promise<any> {
    return this.userKeycloakService.createUser(user);
  }

  async createUserWithoutRoles(user: any): Promise<any> {
    return this.userKeycloakService.createUserWithoutRoles(user);
  }

  async sendVerificationEmail(userId: string, token?: string): Promise<void> {
    return this.userKeycloakService.sendVerificationEmail(userId, token);
  }

  async updateUser(id: string, user: any): Promise<any> {
    return this.userKeycloakService.updateUser(id, user);
  }

  async resetPassword(id: string, newPassword: string): Promise<any> {
    return this.userKeycloakService.resetPassword(id, newPassword);
  }

  async getConnectedUsers(): Promise<any[]> {
    return this.userKeycloakService.getConnectedUsers();
  }

  async findUserById(id: string, token?: string): Promise<any> {
    return this.userKeycloakService.findUserById(id, token);
  }

  async findUserByUsername(username: string, token?: string): Promise<any> {
    return this.userKeycloakService.findUserByUsername(username, token);
  }

  async findUserByEmail(email: string, token?: string): Promise<any> {
    return this.userKeycloakService.findUserByEmail(email, token);
  }

  async findAllUsers(): Promise<UserRepresentation[]> {
    return this.userKeycloakService.findAllUsers();
  }

  async deleteUser(id: string): Promise<void> {
    return this.userKeycloakService.deleteUser(id);
  }



  // ==============================
  // Realm Role Management Endpoints
  // ==============================



  async createRealmRole(roleName: string, description: string): Promise<void> {
    return this.realmRoleService.createRealmRole(roleName, description);
  }

  async deleteRealmRole(roleName: string): Promise<void> {
    return this.realmRoleService.deleteRealmRole(roleName);
  }

  async updateRealmRole(roleName: string, newName?: string, newDescription?: string): Promise<void> {
    return this.realmRoleService.updateRealmRole(roleName, newName, newDescription);
  }

  async getRealmRoleByName(name: string, token: string): Promise<RoleRepresentation[]> {
    return this.realmRoleService.getRealmRoleByName(name, token);
  }

  async assignRealmRole(userId: string, roleName: string, token?: string): Promise<void> {
    return this.realmRoleService.assignRealmRole(userId, roleName, token);
  }

  async deAssignRealmRole(userId: string, roleName: string, token?: string): Promise<void> {
    return this.realmRoleService.deAssignRealmRole(userId, roleName, token);
  }

  async getUserRealmRole(id: string, token?: string): Promise<RoleRepresentation[]> {
    return this.realmRoleService.getUserRealmRole(id, token);
  }

  async findAllUsersByRealmRole(roleName: string, token?: string): Promise<any[]> {
    return this.realmRoleService.findAllUsersByRealmRole(roleName, token);
  }

  async getAllRealmRoles(): Promise<RoleRepresentation[]> {
    return this.realmRoleService.getAllRealmRoles();
  }



  // ==============================
  // Group Management Endpoints
  // ==============================



  async createGroup(groupName: string, attributes?: Record<string, any>): Promise<void> {
    return this.groupService.createGroup(groupName, attributes);
  }

  async updateGroup(groupId: string, groupName?: string, attributes?: Record<string, any>): Promise<void> {
    return this.groupService.updateGroup(groupId, groupName, attributes);
  }

  async deleteGroup(groupId: string): Promise<void> {
    return this.groupService.deleteGroup(groupId);
  }

  async getAllGroups(): Promise<any[]> {
    return this.groupService.getAllGroups();
  }

  async addRoleToGroup(groupId: string, roleName: string): Promise<void> {
    return this.groupService.addRoleToGroup(groupId, roleName);
  }

  async removeRoleFromGroup(groupId: string, roleName: string): Promise<void> {
    return this.groupService.removeRoleFromGroup(groupId, roleName);
  }

  async getGroupRoles(groupId: string): Promise<RoleRepresentation[]> {
    return this.groupService.getGroupRoles(groupId);
  }

  async addUserToGroup(userId: string, groupId: string, token?: string): Promise<void> {
    return this.groupService.addUserToGroup(userId, groupId, token);
  }

  async removeUserFromGroup(userId: string, groupId: string, token?: string): Promise<void> {
    return this.groupService.removeUserFromGroup(userId, groupId, token);
  }

  async getAllUsersFromGroup(groupId: string): Promise<any[]> {
    return this.groupService.getAllUsersFromGroup(groupId);
  }

  async getGroupById(groupId: string): Promise<any> {
    return this.groupService.getGroupById(groupId);
  }

  async getGroupByName(groupName: string): Promise<any> {
    return this.groupService.getGroupByName(groupName);
  }

  async getGroupIdByName(groupName: string): Promise<string> {
    return this.groupService.getGroupIdByName(groupName);
  }

  async getUserGroups(userId: string, token?: string): Promise<any[]> {
    return this.groupService.getUserGroups(userId, token);
  }



  // ==============================
  // Client Role Management Endpoints
  // ==============================



  async createClientRole(roleName: string, description: string): Promise<void> {
    return this.clientRoleService.createClientRole(roleName, description);
  }

  async updateClientRole(roleName: string, newName?: string, newDescription?: string): Promise<void> {
    return this.clientRoleService.updateClientRole(roleName, newName, newDescription);
  }

  async getAllClientRoles(): Promise<any[]> {
    return this.clientRoleService.getAllClientRoles();
  }

  async deleteClientRole(roleName: string): Promise<void> {
    return this.clientRoleService.deleteClientRole(roleName);
  }

  async addClientRoleToGroup(groupId: string, roleName: string): Promise<void> {
    return this.clientRoleService.addClientRoleToGroup(groupId, roleName);
  }

  async removeClientRoleFromGroup(groupId: string, roleName: string): Promise<void> {
    return this.clientRoleService.removeClientRoleFromGroup(groupId, roleName);
  }

  async addClientRoleToUser(userId: string, roleName: string): Promise<void> {
    return this.clientRoleService.addClientRoleToUser(userId, roleName);
  }

  async removeClientRoleFromUser(userId: string, roleName: string): Promise<void> {
    return this.clientRoleService.removeClientRoleFromUser(userId, roleName);
  }

  async findUsersByClientRole(roleName: string): Promise<any[]> {
    return this.clientRoleService.findUsersByClientRole(roleName);
  }

  async findClientRolesByUserId(userId: string): Promise<any[]> {
    return this.clientRoleService.findClientRolesByUserId(userId);
  }


  // ==============================
  // Client Management Endpoints
  // ==============================

  async createClient(clientData: any): Promise<any> {
    return this.clientService.createClient(clientData);
  }

  async deleteClient(clientId: string): Promise<void> {
    return this.clientService.deleteClient(clientId);
  }

  async updateClient(clientId: string, clientData: any): Promise<any> {
    return this.clientService.updateClient(clientId, clientData);
  }

  async getClientByName(clientName: string): Promise<any> {
    return this.clientService.getClientByName(clientName);
  }

  async getClientById(clientId: string): Promise<any> {
    return this.clientService.getClientById(clientId);
  }

  async getAllClients(): Promise<any[]> {
    return this.clientService.getAllClients();
  }

  async addClientRole(clientId: string, roleName: string, description: string): Promise<void> {
    return this.clientService.addClientRole(clientId, roleName, description);
  }

  async removeClientRole(clientId: string, roleName: string): Promise<void> {
    return this.clientService.removeClientRole(clientId, roleName);
  }

  async regenerateClientSecret(clientId: string): Promise<any> {
    return this.clientService.regenerateClientSecret(clientId);
  }

}





