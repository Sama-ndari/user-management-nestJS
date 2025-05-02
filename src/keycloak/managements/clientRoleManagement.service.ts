//src/users/keycloak/managements/clientRole.service.ts
import { forwardRef, HttpException, HttpStatus, Inject, Injectable } from '@nestjs/common';
import { HttpService } from "@nestjs/axios";
import { firstValueFrom } from "rxjs";
import { KeycloakService } from '../keycloak.service';

@Injectable()
export class ClientRoleService {



  constructor(private readonly httpService: HttpService,
    @Inject(forwardRef(() => KeycloakService)) private readonly keycloakService: KeycloakService,
  ) { }


  private async getAdminToken(): Promise<string> {
    return await this.keycloakService.getAdminToken();
  }

  async getClientUuid(token?: string): Promise<string> {
    if (!token) token = await this.getAdminToken();
    return await this.keycloakService.getClientUuid(token);
  }

  // Create a client role
  async createClientRole(roleName: string, description: string): Promise<void> {
    const token = await this.getAdminToken();
    const clientUuid = await this.getClientUuid(token);
    const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/clients/${clientUuid}/roles`;
    const payload = {
      name: roleName,
      description: description,
    };

    try {
      await firstValueFrom(
        this.httpService.post(url, payload, {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }),
      );
      console.log(`Client role '${roleName}' created successfully.`);
    } catch (error) {
      throw new HttpException(`Failed to create role: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async updateClientRole(roleName: string, newName?: string, newDescription?: string): Promise<void> {
    const token = await this.getAdminToken();
    const clientUuid = await this.getClientUuid(token);
    const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/clients/${clientUuid}/roles/${roleName}`;
    const payload: any = {};

    if (newName) payload.name = newName;
    if (newDescription) payload.description = newDescription;

    try {
      await firstValueFrom(
        this.httpService.put(url, payload, {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }),
      );
      console.log(`Client role '${roleName}' updated successfully.`);
    } catch (error) {
      throw new HttpException(`Failed to update role: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async getAllClientRoles(): Promise<any[]> {
    const token = await this.getAdminToken();
    const clientUuid = await this.getClientUuid(token);
    const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/clients/${clientUuid}/roles`;

    try {
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(`Failed to fetch roles: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async deleteClientRole(roleName: string): Promise<void> {
    const token = await this.getAdminToken();
    const clientUuid = await this.getClientUuid(token);
    const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/clients/${clientUuid}/roles/${roleName}`;

    try {
      await firstValueFrom(
        this.httpService.delete(url, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      );
      console.log(`Client role '${roleName}' deleted successfully.`);
    } catch (error) {
      if (error.response?.status === 404) {
        throw new HttpException(`Client role '${roleName}' not found`, HttpStatus.NOT_FOUND);
      }
      if (error.response?.status === 403) {
        throw new HttpException(`Permission denied to delete role '${roleName}'`, HttpStatus.FORBIDDEN);
      }
      throw new HttpException(`Failed to delete role: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async addClientRoleToGroup(groupId: string, roleName: string): Promise<void> {
    const token = await this.getAdminToken();
    const clientUuid = await this.getClientUuid();
    const role = await this.getClientRole(roleName, token, clientUuid);
    const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/groups/${groupId}/role-mappings/clients/${clientUuid}`;

    try {
      await firstValueFrom(
        this.httpService.post(url, [role], {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }),
      );
      console.log(`Client role '${roleName}' added to group '${groupId}'.`);
    } catch (error) {
      throw new HttpException(`Failed to add role to group: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async removeClientRoleFromGroup(groupId: string, roleName: string): Promise<void> {
    const token = await this.getAdminToken();
    const clientUuid = await this.getClientUuid(token);
    const role = await this.getClientRole(roleName, token, clientUuid);
    const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/groups/${groupId}/role-mappings/clients/${clientUuid}`;

    try {
      await firstValueFrom(
        this.httpService.delete(url, {
          headers: { Authorization: `Bearer ${token}` },
          data: [role],
        }),
      );
      console.log(`Client role '${roleName}' removed from group '${groupId}'.`);
    } catch (error) {
      throw new HttpException(`Failed to remove role from group: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async addClientRoleToUser(userId: string, roleName: string): Promise<void> {
    const token = await this.getAdminToken();
    const clientUuid = await this.getClientUuid(token);
    console.log('AddClientRoleToUser',userId, roleName, clientUuid);
    const role = await this.getClientRole(roleName, token, clientUuid);
    console.log('AddClientRoleToUser2',userId, roleName, clientUuid);
    const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/users/${userId}/role-mappings/clients/${clientUuid}`;

    try {
      await firstValueFrom(
        this.httpService.post(url, [role], {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }),
      );
      console.log(`Client role '${roleName}' added to user '${userId}'.`);
    } catch (error) {
      throw new HttpException(`Failed to add role to user: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async removeClientRoleFromUser(userId: string, roleName: string): Promise<void> {
    const token = await this.getAdminToken();
    const clientUuid = await this.getClientUuid(token);
    const role = await this.getClientRole(roleName, token, clientUuid);
    const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/users/${userId}/role-mappings/clients/${clientUuid}`;

    try {
      await firstValueFrom(
        this.httpService.delete(url, {
          headers: { Authorization: `Bearer ${token}` },
          data: [role],
        }),
      );
      console.log(`Client role '${roleName}' removed from user '${userId}'.`);
    } catch (error) {
      throw new HttpException(`Failed to remove role from user: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async findUsersByClientRole(roleName: string): Promise<any[]> {
    const token = await this.getAdminToken();
    const clientUuid = await this.getClientUuid(token);
    // const role = await this.getClientRole(roleName, token, clientUuid);
    const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/clients/${clientUuid}/roles/${roleName}/users`;

    try {
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(`Failed to find users by role: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async findClientRolesByUserId(userId: string): Promise<any[]> {
    const token = await this.getAdminToken();
    const clientUuid = await this.getClientUuid(token);
    const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/users/${userId}/role-mappings/clients/${clientUuid}`;

    try {
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(`Failed to find roles by user ID: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async getClientRole(roleName: string, token?: string, clientUuid?: string): Promise<any> {
    if (!token) token = await this.getAdminToken();
    if (!clientUuid) clientUuid = await this.getClientUuid(token);
    const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/clients/${clientUuid}/roles/${roleName}`;
    const response = await firstValueFrom(
      this.httpService.get(url, {
        headers: { Authorization: `Bearer ${token}` },
      }),
    );
    return response.data;
  }

}





