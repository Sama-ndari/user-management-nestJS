//src/users/keycloak/managements/groupManagement.service.ts
import { forwardRef, HttpException, HttpStatus, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { HttpService } from "@nestjs/axios";
import { firstValueFrom } from "rxjs";
import { KeycloakService } from '../keycloak.service';
import { RoleRepresentation } from '../../users/dto/create-user.dto';

@Injectable()
export class GroupService {
  constructor(private readonly httpService: HttpService,
    @Inject(forwardRef(() => KeycloakService)) private readonly keycloakService: KeycloakService,

  ) { }

  private async getAdminToken(): Promise<string> {
    return await this.keycloakService.getAdminToken();
  }


  async createGroup(groupName: string, attributes?: Record<string, any>): Promise<void> {
    const token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/groups`;
    const payload = {
      name: groupName,
      attributes: {
        description: [attributes?.description ?? 'Group for admin users'],
        createdBy: [attributes?.createdBy ?? 'Admin'],
        isActive: [String(attributes?.isActive ?? true)],
        createdAt: [new Date().toISOString()],
        updatedAt: [new Date().toISOString()],
      },
    };

    console.log('Creating group:', groupName, attributes);

    try {
      await firstValueFrom(
        this.httpService.post(url, payload, {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }),
      );
      console.log(`Group '${groupName}' created successfully.`);
    } catch (error) {
      throw new HttpException(`Failed to create group: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async updateGroup(groupId: string, groupName?: string, attributes?: Record<string, any>): Promise<void> {
    const token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/groups/${groupId}`;
    const payload: any = {};

    if (groupName) {
      payload.name = groupName;
    }
    if (attributes) {
      if (!payload.attributes) {
        payload.attributes = {};
      }
      payload.attributes = Object.entries(attributes || {}).reduce((acc, [key, value]) => {
        if (value !== undefined && value !== null) {
          acc[key] = Array.isArray(value) ? value : [value];
        }
        return acc;
      }, payload.attributes || {});
    }

    try {
      await firstValueFrom(
        this.httpService.put(url, payload, {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }),
      );
      console.log(`Group '${groupId}' updated successfully.`);
    } catch (error) {
      throw new HttpException(`Failed to update group: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async deleteGroup(groupId: string): Promise<void> {
    const token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/groups/${groupId}`;

    try {
      await firstValueFrom(
        this.httpService.delete(url, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }),
      );
      console.log(`Group '${groupId}' deleted successfully.`);
    } catch (error) {
      throw new HttpException(`Failed to delete group: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async getAllGroups(): Promise<any[]> {
    const token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/groups`;

    try {
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }),
      );
      const groups = response.data;

      await Promise.all(
        groups.map(async (group) => {
          group.roles = await this.getGroupRoles(group.id);
        })
      );

      return groups;
    } catch (error) {
      throw new HttpException(`Failed to fetch groups: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async addRoleToGroup(groupId: string, roleName: string): Promise<void> {
    const token = await this.getAdminToken();
    console.log(token);
    const role = await this.keycloakService.getRealmRoleByName(roleName, token);
    console.log(role);
    const roles = [role];
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/groups/${groupId}/role-mappings/realm`;

    try {
      await firstValueFrom(
        this.httpService.post(url, roles, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }),
      );
      console.log(`Role '${roleName}' added to group '${groupId}' successfully.`);
    } catch (error) {
      throw new HttpException(`Failed to add role to group: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async removeRoleFromGroup(groupId: string, roleName: string): Promise<void> {
    const token = await this.getAdminToken();
    const role = await this.keycloakService.getRealmRoleByName(roleName, token);
    const roles = [role];
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/groups/${groupId}/role-mappings/realm`;

    try {
      await firstValueFrom(
        this.httpService.delete(url, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
          data: roles,
        }),
      );
      console.log(`Role '${roleName}' removed from group '${groupId}' successfully.`);
    } catch (error) {
      throw new HttpException(`Failed to remove role from group: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async getGroupRoles(groupId: string): Promise<RoleRepresentation[]> {
    const token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/groups/${groupId}/role-mappings/realm`;

    try {
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(`Failed to fetch roles for group: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async addUserToGroup(userId: string, groupId: string, token?: string): Promise<void> {
    if (!token) token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users/${userId}/groups/${groupId}`;

    try {
      await firstValueFrom(
        this.httpService.put(url, null, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }),
      );
      console.log(`User '${userId}' added to group '${groupId}' successfully.`);
    } catch (error) {
      throw new HttpException(`Failed to add user to group: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async removeUserFromGroup(userId: string, groupId: string, token?: string): Promise<void> {
    if (!token) token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users/${userId}/groups/${groupId}`;

    try {
      await firstValueFrom(
        this.httpService.delete(url, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }),
      );
      console.log(`User '${userId}' removed from group '${groupId}' successfully.`);
    } catch (error) {
      throw new HttpException(`Failed to remove user from group: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async getAllUsersFromGroup(groupId: string): Promise<any[]> {
    const token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/groups/${groupId}/members`;

    try {
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(`Failed to fetch users from group: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async getGroupById(groupId: string): Promise<any> {
    const token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/groups/${groupId}`;

    try {
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(`Failed to fetch group by id: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async getGroupByName(groupName: string): Promise<any> {
    const token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/groups?search=${groupName}`;

    try {
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }),
      );
      const groups = response.data;
      const group = groups.find((g: any) => g.name === groupName);
      if (!group) {
        throw new HttpException(`Group '${groupName}' not found`, HttpStatus.NOT_FOUND);
      }
      return group;
    } catch (error) {
      throw new HttpException(`Failed to fetch group by name: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async getGroupIdByName(groupName: string): Promise<string> {
    const group = await this.getGroupByName(groupName);
    return group.id;
  }

  async getUserGroups(userId: string, token?: string): Promise<any[]> {
    if (!token) {
      token = await this.getAdminToken();
    }
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users/${userId}/groups`;

    try {
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(`Failed to fetch groups for user: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

}





