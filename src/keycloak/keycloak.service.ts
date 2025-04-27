//src/users/keycloak/keycloak.service.ts
import { BadRequestException, HttpException, HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import { HttpService } from "@nestjs/axios";
import { firstValueFrom, lastValueFrom } from "rxjs";
import { CreateUserDatabaseDto, RoleRepresentation, UserRepresentation } from 'src/users/dto/create-user.dto';
import { LoginDto } from 'src/users/dto/login.dto';
import * as jwt from 'jsonwebtoken';
import { DatabaseService } from '../database/database.service';

@Injectable()
export class KeycloakService {



  constructor(private readonly httpService: HttpService,
    private databaseService: DatabaseService,
  ) { }

  async login(userdto: LoginDto): Promise<any> {
    const { identifier, password } = userdto;
    const isEmail = identifier.includes('@');
    const url = `${process.env.KEYCLOAK_LOGIN_URL}`;
    const data = new URLSearchParams();
    data.append('grant_type', 'password');
    data.append('client_id', process.env.KEYCLOAK_CLIENT_ID || '');
    data.append('client_secret', process.env.KEYCLOAK_CLIENT_SECRET || '');
    data.append('username', identifier); // Keycloak can use email as username if configured
    data.append('password', password);

    try {
      const response = await lastValueFrom(
        this.httpService.post(url, data, {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }),
      );

      // Decode the access_token
      // const decoded = await this.decodeJwt(response.data.access_token);

      // Log for debugging
      console.log({
        message: 'Login successful',
        token: response.data.access_token,
        refreshToken: response.data.refresh_token,
        // user: decoded,
      });

      // Return Keycloak response + decoded user data
      return {
        message: 'Login successful',
        access_token: response.data.access_token,
        refresh_token: response.data.refresh_token,
        expires_in: response.data.expires_in,
        token_type: response.data.token_type,
        // user: decoded,
      };
    } catch (error) {
      if (error.response && error.response.status === 401) {
        throw new UnauthorizedException('Invalid credentials');
      }
      throw new HttpException(`Login failed: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  // NEW: Fetch Keycloak public key for verification
  private async getKeycloakPublicKey(): Promise<string> {
    console.log('Fetching Keycloak public key...');
    const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/realms/Waangu-Marketplace/protocol/openid-connect/certs`;
    const response = await firstValueFrom(this.httpService.get(url));
    const cert = response.data.keys[0].x5c[0];
    console.log('Keycloak public key:', cert);
    return `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----`;
  }

  public async decodeJwt(token: string): Promise<any> {
    try {
      // const payload = jwt.decode(token, { complete: false }) as any;
      const publicKey = await this.getKeycloakPublicKey();
      const payload = jwt.verify(token, publicKey, { algorithms: ['RS256'] }) as any; 
      if (!payload) {
        throw new Error('Invalid JWT');
      }

      // Fetch user from DB
      const dbUser: any = await this.databaseService.findUserByKeycloakId(payload.sub);

      // Extract relevant fields from the decoded JWT
      const jwtUser = Object.fromEntries(
        Object.entries({
          keycloakId: payload.sub || '',
          username: payload.preferred_username || '',
          email: payload.email || '',
          name: payload.name || '',
          roles: payload.realm_access?.roles || [],
        }).filter(([_, value]) => value !== undefined && value !== null)
      );

      // Merge the fields from dbUser and jwtUser
      const mergedUser = Object.fromEntries(
        Object.entries({
          id: dbUser._id,
          username: jwtUser.username,
          email: jwtUser.email,
          keycloakId: jwtUser.keycloakId,
          firstName: dbUser?.firstName,
          lastName: dbUser?.lastName,
          phone: dbUser?.phone,
          address: dbUser?.address,
          cardNumber: dbUser?.cardNumber,
          logo: dbUser?.logo,
          status: dbUser?.status || 'pending',
          roles: jwtUser.roles,
        }).filter(([_, value]) => value !== undefined && value !== null && value !== '')
      );

      return mergedUser;
    } catch (error) {
      throw new UnauthorizedException('Failed to decode JWT');
    }
  }

  async refreshAccessToken(refreshToken: string): Promise<{ access: string }> {
    const url = `${process.env.KEYCLOAK_LOGIN_URL}`;
    const data = new URLSearchParams();
    data.append('grant_type', 'refresh_token');
    data.append('client_id', process.env.KEYCLOAK_CLIENT_ID || '');
    data.append('client_secret', process.env.KEYCLOAK_CLIENT_SECRET || '');
    data.append('refresh_token', refreshToken);

    try {
      const response = await lastValueFrom(
        this.httpService.post(url, data, {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }),
      );

      return {
        access: response.data.access_token,
      };
    } catch (error) {
      if (error.response && error.response.status === 400) {
        throw new UnauthorizedException('Invalid refresh token');
      }
      throw new HttpException(
        `Failed to refresh token: ${error.message}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
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
      throw new HttpException(`Logout failed: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
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
      throw new HttpException(`Failed to create user: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    const createdUser = await this.findUserByUsername(user.username);
    await this.assignRole(createdUser.id, user.attributes.role);
    await this.sendVerificationEmail(createdUser.id);
    return createdUser;
  }

  async sendVerificationEmail(userId: string): Promise<void> {
    const token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users/${userId}/execute-actions-email`;
    const actions = ['VERIFY_EMAIL'];
    const queryParams = new URLSearchParams({
      client_id: process.env.KEYCLOAK_CLIENT_ID || 'nestjs-app',
      redirect_uri: process.env.KEYCLOAK_ADMIN_REDIRECT_URL || 'http://google.com', // Adjust to your frontend login page
      lifespan: '43200', // 12 hours in seconds
    });

    try {
      await firstValueFrom(
        this.httpService.put(`${url}?${queryParams.toString()}`, actions, {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }),
      );
      console.log(`Verification email sent for user ${userId}`);
    } catch (error) {
      console.error('Send verification email error:', error.response?.data || error.message);
      throw new HttpException(
        `Failed to send verification email: ${error.response?.data?.errorMessage || error.message}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
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
      throw new HttpException(`Failed to update user: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // Only assign the role if it has been modified
    // if (user.attributes.role !== existingRoles) {
    //   console.log(`Assigning role: ${user.attributes.role}`);
    //   await this.assignRole(id, user.attributes.role);
    // }

    const updatedUser = await this.findUserById(id);
    return updatedUser;
  }

  async resetPassword(id: string, newPassword: string): Promise<any> {
    const token = await this.getAdminToken();
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users/${id}/reset-password`;
    const payload = {
      type: 'password',
      value: newPassword,
      temporary: false, // Set to true if you want to force a password change on next login
    };

    try {
      await firstValueFrom(
        this.httpService.put(url, payload, {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }),
      );
      // Optionally, fetch and return the updated user
      const updatedUser = await this.findUserById(id);
      return updatedUser;
    } catch (error) {
      console.error('Reset password error response:', error.response?.data);
      throw new HttpException(`Failed to reset password: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async getConnectedUsers(): Promise<any[]> {
    const token = await this.getAdminToken();

    // 1. Lookup client UUID
    const clientsRes = await firstValueFrom(
      this.httpService.get(
        `${process.env.KEYCLOAK_ADMIN_BASE_URL}/clients?clientId=${process.env.KEYCLOAK_CLIENT_ID}`,
        { headers: { Authorization: `Bearer ${token}` } },
      )
    );
    const clients = clientsRes.data;
    if (!clients.length) {
      throw new HttpException(
        `Client "${process.env.KEYCLOAK_CLIENT_ID}" not found`,
        HttpStatus.NOT_FOUND,
      );
    }
    const clientUuid = clients[0].id;

    // 2. Fetch active user‑sessions for that client
    const sessionsRes = await firstValueFrom(
      this.httpService.get(
        `${process.env.KEYCLOAK_ADMIN_BASE_URL}/clients/${clientUuid}/user-sessions`,
        { headers: { Authorization: `Bearer ${token}` } },
      )
    );
    const sessions = sessionsRes.data; // Array of UserSessionRepresentation
    if (!sessions.length) { 
      console.log('No active sessions found');
      return [];
    }
    console.log('Sessions:', sessions);
    // 3. Map each session to your DB user
    const connectedUsers = await Promise.all(
      sessions.map(async (s: any) => {
        // Look up the user by their Keycloak sub (userId)
        const dbUser = await this.databaseService.findUserByKeycloakId(s.userId);
        const realmRoles = await this.getUserRole(s.userId, token);
        return {
          userId: s.userId,
          id: dbUser._id,
          username: dbUser.username,
          email: dbUser.email,
          roles: realmRoles.map(r => r.name) || [],   // or whatever roles come back
          sessionStart: s.started || s.start,
          lastAccess: s.lastAccess,
        };
      })
    );

    return connectedUsers;
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
      const user = response.data;

      user.roles = await this.getUserRole(id, token);
      return user;
    } catch (error) {
      throw new HttpException(`Failed to find user by id: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
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
      const user = response.data.length > 0 ? response.data[0] : null;
      if (user) {
        user.roles = await this.getUserRole(user.id, token);
      }
      return user;
    } catch (error) {
      throw new HttpException(`Failed to find user by username: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
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
      const user = response.data.length > 0 ? response.data[0] : null;
      if (user) {
        user.roles = await this.getUserRole(user.id, token);
      }
      return user;
    } catch (error) {
      throw new HttpException(`Failed to find user by email: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
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
      const users = response.data;
      const userRoles = await Promise.all(users.map(user => this.getUserRole(user.id, token)));
      users.forEach((user, index) => { user.roles = userRoles[index]; });
      return users;
    } catch (error) {
      throw new HttpException(`Failed to find users by role: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async findAllUsers(): Promise<UserRepresentation[]> {
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users`;
    const token = await this.getAdminToken();
    try {
      const response = await firstValueFrom(
        this.httpService.get(url, { headers: { Authorization: `Bearer ${token}` } }),
      );
      const users = response.data;
      const userRoles = await Promise.all(users.map(user => this.getUserRole(user.id, token)));
      users.forEach((user, index) => { user.roles = userRoles[index]; });
      return users;
    } catch (error) {
      throw new HttpException(`Find all users failed: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
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
      throw new HttpException(`Failed to delete user: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async createRole(roleName: string, description: string): Promise<void> {
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

  async deleteRole(roleName: string): Promise<void> {
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

  async updateRole(roleName: string, newName?: string, newDescription?: string): Promise<void> {
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
      throw new HttpException(`Role fetch failed: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
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
      throw new HttpException(`Admin token fetch failed: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async getUserRole(id: string, token?: string) {
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

}





