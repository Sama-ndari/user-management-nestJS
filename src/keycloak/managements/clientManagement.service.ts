//src/users/keycloak/managements/clientRole.service.ts
import { forwardRef, HttpException, HttpStatus, Inject, Injectable } from '@nestjs/common';
import { HttpService } from "@nestjs/axios";
import { firstValueFrom } from "rxjs";
import { KeycloakService } from '../keycloak.service';

@Injectable()
export class ClientService {



  constructor(private readonly httpService: HttpService,
    @Inject(forwardRef(() => KeycloakService)) private readonly keycloakService: KeycloakService,
  ) { }


  private async getAdminToken(): Promise<string> {
    return await this.keycloakService.getAdminToken();
  }

  // ==============================
  // Client Management Endpoints
  // ==============================

  async createClient(clientData: any): Promise<any> {
    try {
      const token = await this.getAdminToken();
      const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/clients`;
      const response = await firstValueFrom(
        this.httpService.post(url, clientData, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(`Failed to create client: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async deleteClient(clientId: string): Promise<void> {
    try {
      const token = await this.getAdminToken();
      const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/clients/${clientId}`;
      await firstValueFrom(
        this.httpService.delete(url, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      );
    } catch (error) {
      throw new HttpException(`Failed to delete client: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async updateClient(clientId: string, clientData: any): Promise<any> {
    try {
      const token = await this.getAdminToken();
      const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/clients/${clientId}`;
      const response = await firstValueFrom(
        this.httpService.put(url, clientData, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(`Failed to update client: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async getClientByName(clientName: string): Promise<any> {
    try {
      const token = await this.getAdminToken();
      const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/clients?clientId=${clientName}`;
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      );
      return response.data[0];
    } catch (error) {
      throw new HttpException(`Failed to get client by name: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async getClientById(clientId: string): Promise<any> {
    try {
      const token = await this.getAdminToken();
      const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/clients/${clientId}`;
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(`Failed to get client by ID: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async getAllClients(): Promise<any[]> {
    try {
      const token = await this.getAdminToken();
      const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/clients`;
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      );
      return response.data;
    } catch (error) {
      throw new HttpException(`Failed to get all clients: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async addClientRole(clientId: string, roleName: string, description: string): Promise<void> {
    try {
      const token = await this.getAdminToken();
      const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/clients/${clientId}/roles`;
      const payload = {
        name: roleName,
        description: description,
      };
      await firstValueFrom(
        this.httpService.post(
          url,
          payload,
          {
            headers: {
              Authorization: `Bearer ${token}`,
              'Content-Type': 'application/json',
            },
          },
        ),
      );
    } catch (error) {
      throw new HttpException(`Failed to add client role: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async removeClientRole(clientId: string, roleName: string): Promise<void> {
    try {
      const token = await this.getAdminToken();
      const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/clients/${clientId}/roles/${roleName}`;
      await firstValueFrom(
        this.httpService.delete(url, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      );
    } catch (error) {
      throw new HttpException(`Failed to remove client role: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async regenerateClientSecret(clientId: string): Promise<any> {
    try {
      const token = await this.getAdminToken();
      const client = await this.getClientByName(clientId);
      const url = `${process.env.KEYCLOAK_AUTH_SERVER_URL}/admin/realms/${process.env.KEYCLOAK_REALM}/clients/${client.id}/client-secret`;
      console.log('url', url);
      const response = await firstValueFrom(
        this.httpService.post(url, null, {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json', 
            Accept: 'application/json',
          },
        }),
      );
      console.log('regenerateClientSecret', response.data);
      return response.data;
    } catch (error) {
      throw new HttpException(`Failed to regenerate client secret: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}





