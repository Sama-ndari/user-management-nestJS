//src/keycloak/managements/userManagement.service.ts
import { BadRequestException, forwardRef, HttpException, HttpStatus, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { HttpService } from "@nestjs/axios";
import { firstValueFrom, lastValueFrom } from "rxjs";
import { KeycloakService } from '../keycloak.service';
import { UserRepresentation } from '../../users/dto/create-user.dto';
import { LoginDto } from '../../users/dto/login.dto';
import { DatabaseService } from '../../database/database.service';
import * as jwt from 'jsonwebtoken';
import { EmailService } from 'src/mail/mail.service';

@Injectable()
export class UserKeycloakService {
  constructor(private readonly httpService: HttpService,
    @Inject(forwardRef(() => KeycloakService)) private readonly keycloakService: KeycloakService,
    private readonly databaseService: DatabaseService,
    private readonly emailService: EmailService,

  ) { }

  private async getAdminToken(): Promise<string> {
    return await this.keycloakService.getAdminToken();
  }


  async login(userdto: LoginDto): Promise<any> {
    const { identifier, password } = userdto;
    const url = `${process.env.KEYCLOAK_LOGIN_URL}`;
    const data = new URLSearchParams();
    data.append('grant_type', 'password');
    data.append('client_id', process.env.KEYCLOAK_CLIENT_ID || '');
    data.append('client_secret', process.env.KEYCLOAK_CLIENT_SECRET || '');
    data.append('username', identifier); // Keycloak can use email as username if configured
    data.append('password', password);

    console.log('Login data:', {
      grant_type: data.get('grant_type'),
      client_id: data.get('client_id'),
      client_secret: data.get('client_secret'),
      username: data.get('username'),
      password: data.get('password'),
      url: url,
    });
    try {
      const response = await lastValueFrom(
        this.httpService.post(url, data, {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }),
      );

      console.log({
        message: 'Login successful',
        token: response.data.access_token,
        refreshToken: response.data.refresh_token,
      });

      return {
        message: 'Login successful',
        access_token: response.data.access_token,
        refresh_token: response.data.refresh_token,
        expires_in: response.data.expires_in,
        token_type: response.data.token_type,
      };
    } catch (error) {
      console.error('Login error response:', error.response?.data);
      if (error.response?.status === 401) {
        throw new UnauthorizedException('Invalid credentials');
      }
      throw new HttpException(`Login failed: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  public async decodeJwt(token: string): Promise<any> {
    try {
      // const payload = jwt.decode(token, { complete: false }) as any;
      const publicKey = await this.keycloakService.getKeycloakPublicKey();
      const payload = jwt.verify(token, publicKey, { algorithms: ['RS256'] }) as any;
      if (!payload) throw new Error('Invalid JWT');

      // Fetch user from DB
      const dbUser: any = await this.databaseService.findUserByKeycloakId(payload.sub);
      console.log('Database user:', payload);
      // Extract relevant fields from the decoded JWT
      const jwtUser = Object.fromEntries(
        Object.entries({
          keycloakId: payload.sub || '',
          username: payload.preferred_username || '',
          email: payload.email || '',
          name: payload.name || '',
          roles: payload.realm_access?.roles || [],
          groups: payload.groups || [],
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
          roles: jwtUser.roles, groups: jwtUser.groups
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
    console.log('Creating user...', user);
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
    const groupId = await this.keycloakService.getGroupIdByName(user.attributes.group);
    await this.keycloakService.addUserToGroup(createdUser.id, groupId, token);
    console.log('Created user:', user);
    // Extract the password value from the created user object
    const tempPassword = user.credentials?.find(cred => cred.type === 'password')?.value;
    await this.sendVerificationEmail(createdUser.email, createdUser.username, tempPassword);
    return createdUser;
  }

  async createUserWithoutRoles(user: any): Promise<any> {
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
    // Extract the password value from the created user object
    const tempPassword = user.credentials?.find(cred => cred.type === 'password')?.value;
    await this.sendVerificationEmail(createdUser.email, createdUser.username, tempPassword);
    return createdUser;
  }

  async sendVerificationEmail(userEmail: string, username: string, tempPassword: string): Promise<void> {
    await this.emailService.sendLoginCredentials(userEmail, username, tempPassword);
  }

  async updateUser(id: string, user: any): Promise<any> {
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users/${id}`;

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
      await this.emailService.sendUpdateCredentials(updatedUser.email, updatedUser.username, newPassword);
      return updatedUser;
    } catch (error) {
      console.error('Reset password error response:', error.response?.data);
      throw new HttpException(`Failed to reset password: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async getUserCredentials(identifier: string): Promise<any> {
    const token = await this.getAdminToken();
    let user;

    try {
      // Try to find user by email first
      if (identifier.includes('@')) {
        user = await this.findUserByEmail(identifier, token);
      } else {
        // If not email format, try username
        user = await this.findUserByUsername(identifier, token);
      }

      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users/${user.id}/credentials`;

      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }),
      );

      console.log('response', response.data);

      return {
        userId: user.id,
        username: user.username,
        email: user.email,
        credentials: response.data
      };

    } catch (error) {
      if (error.response?.status === 404) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }
      throw new HttpException(
        `Failed to get user credentials: ${error.message}`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async generateNewPassword(identifier: string): Promise<string> {
    const token = await this.getAdminToken();
    let updatedUser;

    // Try to find user by email first if identifier contains @
    if (identifier.includes('@')) {
      updatedUser = await this.findUserByEmail(identifier, token);
    } else {
      // If not email format, try username
      updatedUser = await this.findUserByUsername(identifier, token);
    }

    if (!updatedUser) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

      identifier = updatedUser.id; // Update identifier to use Keycloak ID
    try {
      // Générer un mot de passe aléatoire
      const newPassword = Math.random().toString(36).slice(-12);
      console.log("Generated password",newPassword);
      const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users/${identifier}/reset-password`;

      await firstValueFrom(
        this.httpService.put(url, 
          {
            type: "password",
            value: newPassword,
            temporary: false
          },
          {
            headers: {
              Authorization: `Bearer ${token}`,
              'Content-Type': 'application/json'
            }
          }
        )
      );

      
      await this.emailService.sendUpdateCredentials(updatedUser.email, updatedUser.username, newPassword);
      return newPassword;

    } catch (error) {
      if (error.response?.status === 404) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }
      throw new HttpException(
        `Failed to generate new password: ${error.message}`,
        HttpStatus.INTERNAL_SERVER_ERROR
      );
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

    // 3. Map each session to your DB user
    const connectedUsers = await Promise.all(
      sessions.map(async (s: any) => {
        // Look up the user by their Keycloak sub (userId)
        const dbUser = await this.databaseService.findUserByKeycloakId(s.userId);
        const realmRoles = await this.keycloakService.getUserRealmRole(s.userId, token);
        const groups = await this.keycloakService.getUserGroups(s.userId, token);
        return {
          userId: s.userId,
          id: dbUser._id,
          username: dbUser.username,
          email: dbUser.email,
          roles: realmRoles.map(r => r.name) || [],
          groups: groups.map(g => g.name) || [],
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

      user.roles = await this.keycloakService.getUserRealmRole(id, token);
      user.groups = await this.keycloakService.getUserGroups(id, token);
      return user;
    } catch (error) {
      throw new HttpException(`Failed to find user by id: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

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
        user.roles = await this.keycloakService.getUserRealmRole(user.id, token);
        user.groups = await this.keycloakService.getUserGroups(user.id, token);
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
        user.roles = await this.keycloakService.getUserRealmRole(user.id, token);
        user.groups = await this.keycloakService.getUserGroups(user.id, token);
      }
      return user;
    } catch (error) {
      throw new HttpException(`Failed to find user by email: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async findAllUsers(): Promise<UserRepresentation[]> {
    const url = `${process.env.KEYCLOAK_ADMIN_BASE_URL}/users`;
    const token = await this.getAdminToken();
    try {
      const response = await firstValueFrom(
        this.httpService.get(url, { headers: { Authorization: `Bearer ${token}` } }),
      );
      console.log('response', response);
      const users = response.data;
      const userRoles = await Promise.all(users.map(user => this.keycloakService.getUserRealmRole(user.id, token)));
      const userGroups = await Promise.all(users.map(user => this.keycloakService.getUserGroups(user.id, token)));
      users.forEach((user, index) => {
        user.roles = userRoles[index];
        user.groups = userGroups[index];
      });
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
}





