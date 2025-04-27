//src/users/transactions/transactions.service.ts
import { HttpException, HttpStatus, Injectable, NotFoundException } from '@nestjs/common';
import { KeycloakService } from '../keycloak/keycloak.service';
import { CreateUserDatabaseDto, CreateUserDto, UserRepresentation } from '../users/dto/create-user.dto';
import { DatabaseService } from '../database/database.service';
import { Connection } from 'mongoose';
import { InjectConnection } from '@nestjs/mongoose';
import { LoginDto } from 'src/users/dto/login.dto';
import { LogoutDto } from 'src/users/dto/logout.dto';
import { PageDto } from 'src/common/page-dto';
import { PageOptionsDto } from 'src/common/page-options-dto';

@Injectable()
export class TransactionsService {
    constructor(
        private keycloakService: KeycloakService,
        private databaseService: DatabaseService,
        @InjectConnection() private readonly connection: Connection,
    ) { }

    async login(userDto: LoginDto): Promise<any> {
        try {
            const keycloakResponse = await this.keycloakService.login(userDto);
            if (!keycloakResponse || !keycloakResponse.access_token) {
                throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
            }

            const dbUser = await this.databaseService.findUserByUsername(userDto.identifier) ||
                await this.databaseService.findUserByEmail(userDto.identifier);
            if (!dbUser) {
                // If the user doesn't exist in your DB, you might choose to create a new entry or throw an error.
                throw new NotFoundException('User not found in database');
            }

            const mergedUser = {
                ...dbUser,
                // username: keycloakUser.username,
                // email: keycloakUser.email,
                // firstName: keycloakUser.firstName,
                // lastName: keycloakUser.lastName,
                // roles: keycloakUser.attributes?.role || [],
                // add additional fields from dbUser as needed
            };

            // 4. Return a payload that includes the authentication tokens and merged user profile.
            return {
                accessToken: keycloakResponse.access_token,
                refreshToken: keycloakResponse.refresh_token,
                // user: mergedUser,
            };
        } catch (error) {
            throw new HttpException(error.message || 'Login failed', HttpStatus.UNAUTHORIZED);
        }
    }
    
    async decodeToken(token: string): Promise<any> {
        try {
            const decodedData = await this.keycloakService.decodeJwt(token);
            return decodedData;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to decode token', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async refreshAccessToken(token: string): Promise<any> {
        try {
            const refreshedToken = await this.keycloakService.refreshAccessToken(token);
            return refreshedToken;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to refresh token', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async logout(token: string): Promise<any> {
        return this.keycloakService.logout(token);
    }

    async createUser(userDto: any): Promise<any> {
        let keycloakId;
        const session = await this.connection.startSession();
        session.startTransaction();

        try {
            const keycloakUserPayload = {
                username: userDto.username,
                email: userDto.email,
                firstName: userDto.firstName,
                lastName: userDto.lastName,
                credentials: userDto.password ? [{ type: 'password', value: userDto.password, temporary: false }] : undefined,
                enabled: true,
                emailVerified: false,
                attributes: {
                    phone: userDto.phone,
                    address: userDto.address,
                    cardNumber: userDto.cardNumber,
                    logo: userDto.logo,
                    status: userDto.status || 'pending',
                    role: userDto.role,
                },
            };

            const createdKeycloakUser = await this.keycloakService.createUser(keycloakUserPayload);
            keycloakId = createdKeycloakUser.id;

            const userForDB = { ...userDto, keycloakId: createdKeycloakUser.id };
            const createdUser = await this.databaseService.createUser(userForDB, session);

            await session.commitTransaction();
            session.endSession();

            return {
                message: 'User created successfully! Please check your email to verify your account.',
                user: createdUser,
                emailSent: createdKeycloakUser.emailVerified ? true : false, // Indicate email status
            };
        } catch (error) {
            await session.abortTransaction();
            session.endSession();

            if (keycloakId) {
                try {
                    await this.keycloakService.deleteUser(keycloakId);
                } catch (compensationError) {
                    console.error('Compensation error:', compensationError.message);
                }
            }

            // Handle email-specific errors gracefully
            if (error.message.includes('Failed to send verification email')) {
                console.warn('User created but email verification failed:', error.message);
                return {
                    message: 'User created successfully, but failed to send verification email. Please verify manually.',
                    user: { username: userDto.username, email: userDto.email },
                    emailSent: false,
                };
            }

            throw new HttpException(error.message || 'Failed to create user', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async updateUser(id: string, userDto: any): Promise<any> {
        // Fetch the user from the database to get the associated Keycloak ID
        const dbUser = await this.databaseService.findUserById(id);
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }

        const keycloakId = dbUser.keycloakId;
        const keycloakOGUser = await this.keycloakService.findUserById(keycloakId);

        // Start a Mongoose session
        const session = await this.connection.startSession();
        session.startTransaction();

        try {
            // ---------------------- STEP 1: Keycloak Operation ----------------------
            // Build the payload for Keycloak. Adjust the payload as required by your Keycloak API.
            const keycloakUserPayload = Object.fromEntries(
                Object.entries({
                    username: userDto.username,
                    email: userDto.email,
                    firstName: userDto.firstName,
                    lastName: userDto.lastName,
                    attributes: {
                        phone: userDto.phone,
                        address: userDto.address,
                        cardNumber: userDto.cardNumber,
                        logo: userDto.logo,
                        status: userDto.status || 'pending',
                        // role: userDto.role || keycloakOGUser.attributes.role,
                    },
                }).filter(([_, value]) => value !== undefined && value !== null)
            );

            // Update the user in Keycloak.
            await this.keycloakService.updateUser(keycloakId, keycloakUserPayload);

            const userForDB = { ...userDto, keycloakId: keycloakId };

            // Pass the Mongoose session into the database service to ensure transactionality.
            const updatedUser = await this.databaseService.updateUser(id, userForDB, session);

            // Commit the transaction if both operations succeed.
            await session.commitTransaction();
            session.endSession();
            return updatedUser;
        } catch (error) {
            // Roll back the database changes
            await session.abortTransaction();
            session.endSession();

            // OPTIONAL: Compensate the Keycloak action by reverting the Keycloak user update if necessary.
            if (error && keycloakOGUser) {
                try {
                    // Revert Keycloak changes if needed (implement revert logic in KeycloakService if applicable)
                    await this.keycloakService.updateUser(keycloakId, keycloakOGUser);
                    console.error('Error occurred, consider reverting Keycloak changes if necessary.');
                } catch (compensationError) {
                    console.error('Compensation error:', compensationError.message);
                }
            }
            throw new HttpException(error.message || 'Failed to update user transactionally', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async resetPassword(id: string, newPassword: string): Promise<any> {
        // Fetch the user from the database to get the associated Keycloak ID
        const dbUser = await this.databaseService.findUserById(id);
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }

        const keycloakId = dbUser.keycloakId;
        return this.keycloakService.resetPassword(keycloakId, newPassword);
    }

    async findUserById(id: string): Promise<any> {
        let keycloakUser: any, dbUser: any;

        try {
            dbUser = await this.databaseService.findUserById(id);
        } catch (error) {
            console.error('Database fetch error:', error.message);
            throw new NotFoundException(`User with id ${id} not found in both systems.`);
        }

        try {
            keycloakUser = await this.keycloakService.findUserById(dbUser.keycloakId);
        } catch (error) {
            // Log error but allow fallback
            console.error('Keycloak fetch error:', error.message);
        }


        console.log('Database user:', dbUser);
        console.log('Keycloak user:', keycloakUser);
        // Prioritize Keycloak values if available and merge with database values
        const mergedUser: UserRepresentation = {
            ...dbUser,
            ...keycloakUser,
        };

        return mergedUser;
    }


    async findUserByUsername(username: string): Promise<any> {
        let keycloakUser: any, dbUser: any;

        try {
            dbUser = await this.databaseService.findUserByUsername(username);
        } catch (error) {
            console.error('Database fetch error:', error.message);
            throw new NotFoundException(`User with username ${username} not found in both systems.`);
        }

        try {
            keycloakUser = await this.keycloakService.findUserByUsername(username);
        } catch (error) {
            // Log error but allow fallback
            console.error('Keycloak fetch error:', error.message);
        }

        console.log('Database user:', dbUser);
        console.log('Keycloak user:', keycloakUser);
        // Prioritize Keycloak values if available and merge with database values
        const mergedUser: UserRepresentation = {
            ...dbUser,
            ...keycloakUser,
        };

        return mergedUser;
    }

    async getConnectedUsers(): Promise<any[]> {
        return this.keycloakService.getConnectedUsers();
    }

    async findAllUsersByRole(roleName: string): Promise<any[]> {
        let keycloakUsers: UserRepresentation[] = [];

        try {
            keycloakUsers = await this.keycloakService.findAllUsersByRole(roleName);
            console.log('Keycloak users:', keycloakUsers);
        } catch (error) {
            // Log error but allow fallback
            console.error('Keycloak fetch error:', error.message);
        }

        // let dbUsers: CreateUserDatabaseDto[] = [];

        // try {
        //     dbUsers = await this.databaseService.findAllUsersByRole(roleName);
        // } catch (error) {
        //     console.error('Database fetch error:', error.message);
        //     throw new NotFoundException(`Users with role ${roleName} not found in both systems.`);
        // }

        // console.log('Database users:', dbUsers);

        // Merge users from both sources, prioritizing Keycloak values if available
        // const mergedUsers: UserRepresentation[] = dbUsers.map(dbUser => {
        //     const keycloakUser = keycloakUsers.find(kcUser => kcUser.id === dbUser.keycloakId);
        //     return {
        //         ...dbUser,
        //         ...keycloakUser,
        //     };
        // });

        return keycloakUsers;
    }

    async findAllUsers(pageOptionsDto: PageOptionsDto): Promise<PageDto<CreateUserDatabaseDto>> {
        let keycloakUsers: any[] = [];
        let dbUsers;

        try {
            dbUsers = await this.databaseService.findAllUsers(pageOptionsDto);
        } catch (error) {
            console.error('Database fetch error:', error.message);
            throw new NotFoundException('Users not found in the database.');
        }

        try {
            keycloakUsers = await this.keycloakService.findAllUsers();
        } catch (error) {
            // Log error but allow fallback
            console.error('Keycloak fetch error:', error.message);
        }

        console.log('Database users:', dbUsers.data);
        console.log('Keycloak users:', keycloakUsers);
        // Merge users from both sources, prioritizing Keycloak values if available
        const mergedUsers: CreateUserDatabaseDto[] = dbUsers.data.map(dbUser => {
            const keycloakUser = keycloakUsers.find(kcUser => kcUser.id === dbUser.keycloakId);
            return {
                ...dbUser,
                ...keycloakUser,
            };
        });
        console.log('Merged users:', mergedUsers);

        return new PageDto(mergedUsers, dbUsers.meta);
    }

    async findUserByEmail(email: string): Promise<any> {
        let keycloakUser: any, dbUser: any;

        try {
            dbUser = await this.databaseService.findUserByEmail(email);
        } catch (error) {
            console.error('Database fetch error:', error.message);
            throw new NotFoundException(`User with email ${email} not found in both systems.`);
        }

        try {
            keycloakUser = await this.keycloakService.findUserByEmail(email);
        } catch (error) {
            // Log error but allow fallback
            console.error('Keycloak fetch error:', error.message);
        }

        console.log('Database user:', dbUser);
        console.log('Keycloak user:', keycloakUser);
        // Prioritize Keycloak values if available and merge with database values
        const mergedUser: UserRepresentation = {
            ...dbUser,
            ...keycloakUser,
        };

        return mergedUser;
    }

    async deleteUser(id: string): Promise<any> {
        // Start a Mongoose session
        const session = await this.connection.startSession();
        session.startTransaction();

        try {
            // Fetch the user from the database to get the associated Keycloak ID
            const dbUser = await this.databaseService.findUserById(id);
            if (!dbUser || !dbUser.keycloakId) {
                throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
            }

            const keycloakId = dbUser.keycloakId;

            // Delete the user in Keycloak
            await this.keycloakService.deleteUser(keycloakId);
            console.log('Keycloak user deleted');

            // Pass the Mongoose session into the database service to ensure transactionality
            const deletedUserDB = await this.databaseService.deleteUser(id, session);
            console.log('Database user deleted');

            // Commit the transaction if both operations succeed
            await session.commitTransaction();
            session.endSession();
            return deletedUserDB;
        } catch (error) {
            // Roll back the database changes
            await session.abortTransaction();
            session.endSession();

            // OPTIONAL: Compensate the Keycloak action by recreating the Keycloak user if necessary
            console.error('Error occurred during user deletion:', error.message);
            throw new HttpException(error.message || 'Failed to delete user transactionally', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async createRole(roleName: string, description: string): Promise<any> {
        try {
            const createdRole = await this.keycloakService.createRole(roleName, description);
            return createdRole;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to create role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async deleteRole(roleName: string): Promise<any> {
        try {
            await this.keycloakService.deleteRole(roleName);
            return { message: `Role ${roleName} deleted successfully` };
        } catch (error) {
            throw new HttpException(error.message || 'Failed to delete role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async updateRole(roleName: string, newName?: string, newDescription?: string): Promise<any> {
        try {
            const updatedRole = await this.keycloakService.updateRole(roleName, newName, newDescription);
            return updatedRole;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to update role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async assignRole(userId: string, roleName: string): Promise<void> {
        const dbUser = await this.databaseService.findUserById(userId);
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        await this.keycloakService.assignRole(dbUser.keycloakId, roleName);
        // // Start a Mongoose session
        // const session = await this.connection.startSession();
        // session.startTransaction();

        // try {
        //     // Use the Keycloak ID to assign the role in Keycloak
        //     await this.keycloakService.assignRole(dbUser.keycloakId, roleName);

        //     // Update the role in the database within the transaction
        //     await this.databaseService.updateUserRole(userId, roleName, true, session);

        //     // Commit the transaction if both operations succeed
        //     await session.commitTransaction();
        //     session.endSession();
        // } catch (error) {
        //     // Roll back the database changes
        //     await session.abortTransaction();
        //     session.endSession();

        //     // Rollback: De-assign role in Keycloak if database update fails
        //     try {
        //         await this.keycloakService.deAssignRole(userId, roleName);
        //     } catch (compensationError) {
        //         console.error('Compensation error:', compensationError.message);
        //     }

        //     throw new HttpException(error.message || 'Failed to assign role transactionally', HttpStatus.INTERNAL_SERVER_ERROR);
        // }
    }

    async deAssignRole(userId: string, roleName: string): Promise<void> {
        const dbUser = await this.databaseService.findUserById(userId);
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        await this.keycloakService.deAssignRole(dbUser.keycloakId, roleName);
        // // Start a Mongoose session
        // const session = await this.connection.startSession();
        // session.startTransaction();

        // try {
        //     // Use the Keycloak ID to de-assign the role in Keycloak
        //     await this.keycloakService.deAssignRole(dbUser.keycloakId, roleName);

        //     // Update the role in the database within the transaction
        //     await this.databaseService.updateUserRole(userId, roleName, false, session);

        //     // Commit the transaction if both operations succeed
        //     await session.commitTransaction();
        //     session.endSession();
        // } catch (error) {
        //     // Roll back the database changes
        //     await session.abortTransaction();
        //     session.endSession();

        //     // Rollback: Re-assign role in Keycloak if database update fails
        //     try {
        //         await this.keycloakService.assignRole(dbUser.keycloakId, roleName);
        //     } catch (compensationError) {
        //         console.error('Compensation error:', compensationError.message);
        //     }

        //     throw new HttpException(error.message || 'Failed to de-assign role transactionally', HttpStatus.INTERNAL_SERVER_ERROR);
        // }
    }
}