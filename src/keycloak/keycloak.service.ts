import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import KeycloakAdminClient from 'keycloak-admin';
import { HttpService } from "@nestjs/axios";
import { firstValueFrom, lastValueFrom } from "rxjs";
import { RoleRepresentation, UserRepresentation } from 'src/users/dto/create-user.dto';
import { LoginDto } from 'src/users/dto/login.dto';

@Injectable()
export class KeycloakService {

  constructor(
    private readonly httpService: HttpService,) {
  }

  async login(userdto: LoginDto): Promise<any> {
    const url = `${process.env.KEYCLOAK_LOGIN_URL}`;
    const data = new URLSearchParams();
    data.append('grant_type', 'password');
    data.append('client_id', process.env.KEYCLOAK_CLIENT_ID || '');
    data.append('client_secret', process.env.KEYCLOAK_CLIENT_SECRET || '');
    data.append('username', userdto.username);
    data.append('password', userdto.password);

    try {
      const response = await lastValueFrom(
        this.httpService.post(url, data, {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }),
      );
      console.log({ message: 'Login successful', token: response.data.access_token, refreshToken: response.data.refresh_token });
      return response.data; // Contains access_token, refresh_token, etc.
    } catch (error) {
      if (error.response && error.response.status === 401) {
        throw new UnauthorizedException('Invalid credentials');
      }
      throw error; // Propagate other errors
    }
  }

  async logout(refreshToken: string): Promise<void> {
    const url = `${process.env.KEYCLOAK_LOGOUT_URL}`;
    const data = new URLSearchParams();
    data.append('client_id', process.env.KEYCLOAK_CLIENT_ID || '');
    data.append('client_secret', process.env.KEYCLOAK_CLIENT_SECRET || '');
    data.append('token', refreshToken);
    data.append('token_type_hint', 'refresh_token');

    try {
      await lastValueFrom(
        this.httpService.post(url, data, {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }),
      );
      console.log('Logout successful');
    } catch (error) {
      throw error; // Propagate errors for debugging
    }
  }

  async createUser(user: any): Promise<any> {
    // Fetch admin token
    const token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users`;

    // Check for existing users
    const existingUserByUsername = await this.findUserByUsername(user.username, token);
    if (existingUserByUsername) {
      throw new BadRequestException(`Username '${user.username}' is already taken.`);
    }

    const existingUserByEmail = await this.findUserByEmail(user.email, token);
    if (existingUserByEmail) {
      throw new BadRequestException(`Email '${user.email}' is already in use.`);
    }
    try {
      const response = await firstValueFrom(
        this.httpService.post(url, user, {
          headers: {
            Authorization: `Bearer ${token}`
          },
        }));
    } catch (error) {
      throw new Error(`Failed to create user: ${error.message}`);
    }

    const createdUser = await this.findUserByUsername(user.username);
    await this.assignRole(createdUser.id, user.attributes.role);
    // await this.keycloakService.sendVerificationEmail(user, token);
    return createdUser;
  }

  async updateUser(id: string, user: any): Promise<any> {
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users/${id}`;

    // const existingUser = await this.findUserById(id);
    // const existingRoles = existingUser.attributes.role || [];

    try {
      await firstValueFrom(
        this.httpService.put(url, user, {
          headers: {
            Authorization: `Bearer ${await this.getAdminToken()}`,
          },
        }),
      );
    } catch (error) {
      throw new Error(`Failed to update user: ${error.message}`);
    }

    // Only assign the role if it has been modified
    // if (user.attributes.role !== existingRoles) {
    //   console.log(`Assigning role: ${user.attributes.role}`);
    //   await this.assignRole(id, user.attributes.role);
    // }

    const updatedUser = await this.findUserById(id);
    return updatedUser;
  }


  async findUserById(id: string, token?: string): Promise<any> {
    if (!token) {
      token = await this.getAdminToken();
    }
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users/${id}`;
    try {
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      );
      return response.data;
    } catch (error) {
      throw new Error(`Failed to find user by id: ${error.message}`);
    }
  }

  // Helper method to find a user by username
  async findUserByUsername(username: string, token?: string): Promise<any> {
    if (!token) {
      token = await this.getAdminToken();
    }
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users?username=${username}&exact=true`;
    try {
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      );
      return response.data.length > 0 ? response.data[0] : null;
    } catch (error) {
      throw new Error(`Failed to find user by username: ${error.message}`);
    }
  }

  async findUserByEmail(email: string, token?: string): Promise<any> {
    if (!token) {
      token = await this.getAdminToken();
    }
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users?email=${email}&exact=true`;
    try {
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      );
      return response.data.length > 0 ? response.data[0] : null;
    } catch (error) {
      throw new Error(`Failed to find user by email: ${error.message}`);
    }
  }

  async findAllUsersByRole(roleName: string, token?: string): Promise<any[]> {
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
      return response.data;
    } catch (error) {
      throw new Error(`Failed to find users by role: ${error.message}`);
    }
  }

  async findAllUsers(): Promise<UserRepresentation[]> {
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users`;
    try {
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: {
            Authorization: `Bearer ${await this.getAdminToken()}`,
          },
        }),
      );
      return response.data;
    } catch (error) {
      throw new Error(`Failed to find all users: ${error.message}`);
    }
  }

  async deleteUser(id: string): Promise<void> {
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users/${id}`;
    try {
      await firstValueFrom(
        this.httpService.delete(url, {
          headers: {
            Authorization: `Bearer ${await this.getAdminToken()}`,
          },
        }),
      );
    } catch (error) {
      throw new Error(`Failed to delete user: ${error.message}`);
    }
  }

  async getRoleByName(name: string, token: string): Promise<RoleRepresentation[]> {
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
      console.error(`Error in getRoleByName: ${error.message}`);
      throw new Error(`Failed to fetch role by name: ${error.message}`);
    }
  }

  async assignRole(userId: string, roleName: string) {
    console.log(`Function: assignRole, userId: ${userId}, roleName: ${roleName}`);
    const token = await this.getAdminToken();
    const role = await this.getRoleByName(roleName, token);
    const roles = [role];
    console.log(`Function: assignRole, Roles: ${JSON.stringify(roles)}`);
    await firstValueFrom(this.httpService.post(`${process.env.KEYCLOAK_ADMIN_BASE_URL}/users/${userId}/role-mappings/realm`, roles, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }),

    );
  }

  async deAssignRole(userId: string, roleName: string) {
    const token = await this.getAdminToken();
    const role = await this.getRoleByName(roleName, token);
    const roles = [role];
    await firstValueFrom(this.httpService.delete(`${process.env.KEYCLOAK_ADMIN_BASE_URL}/users/${userId}/role-mappings/realm`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      data: roles,
    }),
    );
  }

  async getAdminToken(): Promise<string> {
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
      throw new Error(`Failed to get admin token: ${error.message}`);
    }
  }

}





