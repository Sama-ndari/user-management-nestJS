import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as vault from 'node-vault';

@Injectable()
export class VaultService implements OnModuleInit {

  private readonly logger = new Logger(VaultService.name);
  private client: vault.client;
  private engine: string;

  constructor(private readonly configService: ConfigService) { }

  async onModuleInit() {
    await this.initializeVaultClient();
  }

  private async initializeVaultClient(): Promise<void> {
    const options: vault.VaultOptions = {
      apiVersion: 'v1',
      endpoint: process.env.VAULT_ADDR,
      token: process.env.VAULT_TOKEN,
      namespace: this.configService.get<string>('VAULT_NAMESPACE'),
    };

    this.engine = this.configService.get<string>('VAULT_ENGINE') || 'secret';
    this.client = vault(options);
    try {
      await this.client.health();
      this.logger.log('Successfully connected to Vaults');
    } catch (error) {
      this.logger.error('Failed to connect to Vault', error.stack);
      throw error;
    }
  }

  async getSecret(path: string): Promise<any> {
    try {
      // const fullPath = `${this.engine}/${path}`;
      const fullPath = `${path}`;
      const response = await this.client.read(fullPath);
      return response.data.data || response.data; 
    } catch (error) {
      this.logger.error(`Failed to read secret from path: ${path}`, error.stack);
      throw new Error(`Failed to retrieve secret: ${error.message}`);
    }
  }

  async writeSecret(path: string, data: any): Promise<void> {
    try {
      const fullPath = `${this.engine}/${path}`;
      await this.client.write(fullPath, data);
      this.logger.log(`Successfully wrote secret to path: ${path}`);
    } catch (error) {
      this.logger.error(`Failed to write secret to path: ${path}`, error.stack);
      throw new Error(`Failed to store secret: ${error.message}`);
    }
  }

  async listSecrets(path: string): Promise<string[]> {
    try {
      const fullPath = `${this.engine}/${path}`;
      const response = await this.client.list(fullPath);
      return response.data.keys || [];
    } catch (error) {
      this.logger.error(`Failed to list secrets at path: ${path}`, error.stack);
      throw new Error(`Failed to list secrets: ${error.message}`);
    }
  }

  async deleteSecret(path: string): Promise<void> {
    try {
      const fullPath = `${this.engine}/${path}`;
      await this.client.delete(fullPath);
      this.logger.log(`Successfully deleted secret at path: ${path}`);
    } catch (error) {
      this.logger.error(`Failed to delete secret at path: ${path}`, error.stack);
      throw new Error(`Failed to delete secret: ${error.message}`);
    }
  }

  async renewToken(): Promise<void> {
    try {
      await this.client.tokenRenewSelf();
      this.logger.log('Vault token renewed successfully');
    } catch (error) {
      this.logger.error('Failed to renew Vault token', error.stack);
      throw new Error(`Failed to renew token: ${error.message}`);
    }
  }
}
