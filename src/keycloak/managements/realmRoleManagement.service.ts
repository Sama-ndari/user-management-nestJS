//src/users/keycloak/managements/realmRole.service.ts
import { forwardRef, HttpException, HttpStatus, Inject, Injectable } from '@nestjs/common';
import { HttpService } from "@nestjs/axios";
import { firstValueFrom } from "rxjs";
import { KeycloakService } from '../keycloak.service';
import { RoleRepresentation } from '../../users/dto/create-user.dto';

@Injectable()
export class RealmRoleService {
  constructor(private readonly httpService: HttpService,
    @Inject(forwardRef(() => KeycloakService)) private readonly keycloakService: KeycloakService,
  ) { }

  private async getAdminToken(): Promise<string> {
    return await this.keycloakService.getAdminToken();
  }

  async createRealmRole(roleName: string, description: string): Promise<void> {
    const token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/roles`;
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
      console.log(`Role '${roleName}' created successfully.`);
    } catch (error) {
      throw new HttpException(`Failed to create role: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async deleteRealmRole(roleName: string): Promise<void> {
    const token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/roles/${roleName}`;

    try {
      await firstValueFrom(
        this.httpService.delete(url, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }),
      );
      console.log(`Role '${roleName}' deleted successfully.`);
    } catch (error) {
      throw new HttpException(`Failed to delete role: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async updateRealmRole(roleName: string, newName?: string, newDescription?: string): Promise<void> {
    const token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/roles/${roleName}`;
    const payload: any = {};

    // Update name if provided
    if (newName) {
      payload.name = newName;
    }

    // Update description if provided
    if (newDescription) {
      payload.description = newDescription;
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
      console.log(`Role '${roleName}' updated successfully.`);
    } catch (error) {
      throw new HttpException(`Failed to update role: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async getRealmRoleByName(name: string, token: string): Promise<RoleRepresentation[]> {
    console.log(`Function: getRoleByName, name: ${name}`);
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/roles/${name}`;
    try {
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }),
      );
      console.log(`Function: getRoleByName, URL: ${url}, Response: ${response.data}`);
      return response.data;
    } catch (error) {
      throw new HttpException(`Role fetch failed: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async assignRealmRole(userId: string, roleName: string, token?: string) {
    console.log(`Function: assignRole, userId: ${userId}, roleName: ${roleName}`);
    if (!token) {
      token = await this.getAdminToken();
    }
    const role = await this.getRealmRoleByName(roleName, token);
    const roles = [role];
    console.log(`Function: assignRole, Roles: ${JSON.stringify(roles)}`);
    await firstValueFrom(this.httpService.post(`${process.env.KEYCLOAK_ADMIN_BASE_URL}/users/${userId}/role-mappings/realm`, roles, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }),

    );
  }

  async deAssignRealmRole(userId: string, roleName: string, token?: string) {
    if (!token) {
      token = await this.getAdminToken();
    }
    const role = await this.getRealmRoleByName(roleName, token);
    const roles = [role];
    await firstValueFrom(this.httpService.delete(`${process.env.KEYCLOAK_ADMIN_BASE_URL}/users/${userId}/role-mappings/realm`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      data: roles,
    }),
    );
  }

  async getUserRealmRole(id: string, token?: string) {
    if (!token) {
      token = await this.getAdminToken();
    }
    // Fetch roles for the user
    const rolesUrl = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users/${id}/role-mappings/realm`;
    const rolesResponse = await firstValueFrom(
      this.httpService.get(rolesUrl, {
        headers: { Authorization: `Bearer ${token}` },
      }),
    );
    const roles = rolesResponse.data;
    // roles.shift(); // Remove the first element
    return roles;

  }

  async findAllUsersByRealmRole(roleName: string, token?: string): Promise<any[]> {
    if (!token) {
      token = await this.getAdminToken();
    }
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/roles/${roleName}/users`;
    try {
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      );
      const users = response.data;
      const userRoles = await Promise.all(users.map(user => this.getUserRealmRole(user.id, token)));
      const userGroups = await Promise.all(users.map(user => this.keycloakService.getUserGroups(user.id, token)));
      users.forEach((user, index) => {
        user.roles = userRoles[index];
        user.groups = userGroups[index];
      });
      return users;
    } catch (error) {
      throw new HttpException(`Failed to find users by role: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async getAllRealmRoles(): Promise<RoleRepresentation[]> {
    const token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/roles`;

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
      throw new HttpException(`Failed to fetch roles: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}





