//src/users/transactions/transactions.service.ts
import { HttpException, HttpStatus, Injectable, NotFoundException } from '@nestjs/common';
import { KeycloakService } from '../keycloak/keycloak.service';
import { CreateUserDatabaseDto, CreateUserDto, UserRepresentation } from '../users/dto/create-user.dto';
import { DatabaseService } from '../database/database.service';
import { Connection } from 'mongoose';
import { InjectConnection } from '@nestjs/mongoose';
import { LoginDto } from 'src/users/dto/login.dto';
import { LogoutDto } from 'src/users/dto/logout.dto';
import { PageDto } from 'src/common/page-dto/page-dto';
import { PageOptionsDto } from 'src/common/page-options-dto/page-options-dto';
import { LoggerService } from '../keycloak/security/logger.service';
import { UserActions } from '../users/entities/enumerate.entity';

@Injectable()
export class TransactionsService {
    constructor(
        private keycloakService: KeycloakService,
        private databaseService: DatabaseService,
        @InjectConnection() private readonly connection: Connection,
        private readonly loggerService: LoggerService,
    ) { }



  // ==============================
  // Miscellaneous Endpoints
  // ==============================



    async getAuditLogs(filters: { date?: string; actor?: string; action?: string; startTime?: string; endTime?: string; }): Promise<any> {
        const logs = await this.keycloakService.getAuditLogs({ date: filters.date || undefined, actor: filters.actor || undefined, action: filters.action || undefined, startTime: filters.startTime || undefined, endTime: filters.endTime || undefined });
        return logs;
    }

    async deleteAuditLogs(
        filters: { 
            date?: string; 
            actor?: string; 
            action?: string; 
            startTime?: string; 
            endTime?: string; }): Promise<{ deletedCount: number }> {
        const logs = await this.keycloakService.deleteAuditLogs({ date: filters.date || undefined, actor: filters.actor || undefined, action: filters.action || undefined, startTime: filters.startTime || undefined, endTime: filters.endTime || undefined });
        return logs;
    }
    async getAllActions(): Promise<string[]> {
        try {
            return await Object.values(UserActions);
        } catch (error) {
            throw new HttpException(error.message || 'Failed to get all actions', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }



  // ==============================
  // User Management Endpoints
  // ==============================



    async login(userDto: LoginDto): Promise<any> {
        try {
            const keycloakResponse = await this.keycloakService.login(userDto);
            if (!keycloakResponse || !keycloakResponse.access_token) {
                throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
            }

            const logData = {
                usernameOrEmail: userDto.identifier,
                accessToken: keycloakResponse.access_token ? 'Token generated' : 'No token',
            };
            this.loggerService.logAction('USER_LOGIN', 'User login attempt', logData);

            return {
                accessToken: keycloakResponse.access_token,
                refreshToken: keycloakResponse.refresh_token,
            };
        } catch (error) {
            throw new HttpException(error.message || 'Login failed', HttpStatus.UNAUTHORIZED);
        }
    }

    async decodeToken(token: string): Promise<any> {
        try {
            const decodedData = await this.keycloakService.decodeJwt(token);
            this.loggerService.logAction('DECODE_TOKEN', 'Decoding JWT token', { decodedData });
            return decodedData;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to decode token', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async refreshAccessToken(token: string): Promise<any> {
        try {
            const refreshedToken = await this.keycloakService.refreshAccessToken(token);
            this.loggerService.logAction('REFRESH_ACCESS_TOKEN', 'Refreshing access token', { tokenRefreshed: !!refreshedToken });
            return refreshedToken;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to refresh token', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async logout(token: string): Promise<any> {
        try {
            const logoutResponse = await this.keycloakService.logout(token);
            this.loggerService.logAction('USER_LOGOUT', 'User logout attempt', { tokenInvalidated: logoutResponse });
            return logoutResponse;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to logout', HttpStatus.INTERNAL_SERVER_ERROR);
        }
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
                    group: userDto.group,
                },
            };

            const createdKeycloakUser = await this.keycloakService.createUser(keycloakUserPayload);
            keycloakId = createdKeycloakUser.id;

            const userForDB = { ...userDto, keycloakId: createdKeycloakUser.id };
            const createdUser = await this.databaseService.createUser(userForDB, session);

            await session.commitTransaction();
            session.endSession();

            const logData = {
                username: createdUser.username,
                email: createdUser.email,
                keycloakId: createdUser.keycloakId,
                status: createdUser.status,
            };
            this.loggerService.logAction('CREATE_USER', 'User created successfully', logData);

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

    async createUserWithoutRoles(userDto: any): Promise<any> {
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
                },
            };

            const createdKeycloakUser = await this.keycloakService.createUserWithoutRoles(keycloakUserPayload);
            keycloakId = createdKeycloakUser.id;

            const userForDB = { ...userDto, keycloakId: createdKeycloakUser.id };
            const createdUser = await this.databaseService.createUser(userForDB, session);

            await session.commitTransaction();
            session.endSession();

            const logData = {
                username: createdUser.username,
                email: createdUser.email,
                keycloakId: createdUser.keycloakId,
                status: createdUser.status,
            };
            this.loggerService.logAction('CREATE_USER_WITHOUT_ROLES', 'User created successfully without roles', logData);

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

            // Log the action with updated user data
            const mergedUser: UserRepresentation = {
                ...dbUser,
                ...keycloakUserPayload,
            };
            this.loggerService.logAction('UPDATE_USER', 'User updated successfully', { updatedData: mergedUser });

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
        const resetResponse = await this.keycloakService.resetPassword(keycloakId, newPassword);

        // Log the action with relevant data
        this.loggerService.logAction('RESET_PASSWORD', 'Password reset successfully', {
            userId: id,
            keycloakId: keycloakId,
            resetStatus: resetResponse ? 'Success' : 'Failed',
        });

        return resetResponse;
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

        this.loggerService.logAction('FIND_USER_BY_ID', "Fetching user by ID", { returnedData: mergedUser });

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

        this.loggerService.logAction('FIND_USER_BY_USERNAME', "Fetching user by username", { returnedData: mergedUser });

        return mergedUser;
    }

    async getConnectedUsers(): Promise<any[]> {
        const connectedUsers = await this.keycloakService.getConnectedUsers();
        this.loggerService.logAction('GET_CONNECTED_USERS', "Fetching connected users", { returnedData: connectedUsers });
        return connectedUsers;
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
        this.loggerService.logAction('LIST_USERS', "Getting all Users", { returnedData: mergedUsers });
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

        this.loggerService.logAction('FIND_USER_BY_EMAIL', "Fetching user by email", { returnedData: mergedUser });

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

            // Pass the Mongoose session into the database service to ensure transactionality
            const deletedUserDB = await this.databaseService.deleteUser(id, session);
            console.log('Database user deleted');

            // Delete the user in Keycloak
            await this.keycloakService.deleteUser(keycloakId);
            console.log('Keycloak user deleted');

            // Commit the transaction if both operations succeed
            await session.commitTransaction();
            session.endSession();

            this.loggerService.logAction('DELETE_USER', "User deleted successfully", { userId: id, keycloakId });

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



  // ==============================
  // Realm Role Management Endpoints
  // ==============================




    async createRealmRole(roleName: string, description: string): Promise<any> {
        try {
            const createdRole = await this.keycloakService.createRealmRole(roleName, description);
            this.loggerService.logAction('CREATE_ROLE', 'Role created successfully', { roleName, description });
            return createdRole;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to create role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async deleteRealmRole(roleName: string): Promise<any> {
        try {
            await this.keycloakService.deleteRealmRole(roleName);
            this.loggerService.logAction('DELETE_ROLE', 'Role deleted successfully', { roleName });
            return { message: `Role ${roleName} deleted successfully` };
        } catch (error) {
            throw new HttpException(error.message || 'Failed to delete role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async updateRealmRole(roleName: string, newName?: string, newDescription?: string): Promise<any> {
        try {
            const updatedRole = await this.keycloakService.updateRealmRole(roleName, newName, newDescription);
            this.loggerService.logAction('UPDATE_ROLE', 'Role updated successfully', { roleName, newName, newDescription });
            return updatedRole;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to update role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async assignRealmRole(userId: string, roleName: string): Promise<void> {
        const dbUser = await this.databaseService.findUserById(userId);
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        await this.keycloakService.assignRealmRole(dbUser.keycloakId, roleName);
        this.loggerService.logAction('ASSIGN_ROLE', 'Role assigned to user', { userId, roleName });
    }

    async deAssignRealmRole(userId: string, roleName: string): Promise<void> {
        const dbUser = await this.databaseService.findUserById(userId);
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        await this.keycloakService.deAssignRealmRole(dbUser.keycloakId, roleName);
        this.loggerService.logAction('DE_ASSIGN_ROLE', 'Role de-assigned from user', { userId, roleName });
    }

    async getAllRealmRoles(): Promise<any[]> {
        try {
            const roles = await this.keycloakService.getAllRealmRoles();
            this.loggerService.logAction('GET_ALL_ROLES', 'Fetched all roles', { returnedData: roles });
            return roles;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch roles', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async findAllUsersByRealmRole(roleName: string): Promise<any[]> {
        let keycloakUsers: UserRepresentation[] = [];

        try {
            keycloakUsers = await this.keycloakService.findAllUsersByRealmRole(roleName);
            console.log('Keycloak users:', keycloakUsers);
        } catch (error) {
            console.error('Keycloak fetch error:', error.message);
        }
        this.loggerService.logAction('LIST_USERS_BY_ROLE', `Getting all Users by Role: {roleName}`, { roleName, returnedData: keycloakUsers });
        return keycloakUsers;
    }

    async getUserRealmRoles(userId: string): Promise<any[]> {
        const dbUser = await this.databaseService.findUserById(userId);
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        try {
            const roles = await this.keycloakService.getUserRealmRole(dbUser.keycloakId);
            this.loggerService.logAction('GET_USER_ROLES', 'Fetched user roles', { userId, returnedData: roles });
            return roles;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch user roles', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }



  // ==============================
  // Group Management Endpoints
  // ==============================




    async createGroup(groupName: string, attributes?: Record<string, any>): Promise<any> {
        try {
            const createdGroup = await this.keycloakService.createGroup(groupName, attributes);
            this.loggerService.logAction('CREATE_GROUP', 'Group created successfully', { groupName, attributes });
            return createdGroup;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to create group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async updateGroup(groupId: string, groupName?: string, attributes?: Record<string, any>): Promise<any> {
        try {
            const updatedGroup = await this.keycloakService.updateGroup(groupId, groupName, attributes);
            this.loggerService.logAction('UPDATE_GROUP', 'Group updated successfully', { groupId, groupName, attributes });
            return updatedGroup;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to update group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async deleteGroup(groupId: string): Promise<any> {
        try {
            const deletedGroup = await this.keycloakService.deleteGroup(groupId);
            this.loggerService.logAction('DELETE_GROUP', 'Group deleted successfully', { groupId });
            return deletedGroup;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to delete group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getAllGroups(): Promise<any[]> {
        try {
            const groups = await this.keycloakService.getAllGroups();
            this.loggerService.logAction('GET_ALL_GROUPS', 'Fetched all groups', { returnedData: groups });
            return groups;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch groups', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async addRoleToGroup(groupId: string, roleName: string): Promise<any> {
        try {
            const result = await this.keycloakService.addRoleToGroup(groupId, roleName);
            this.loggerService.logAction('ADD_ROLE_TO_GROUP', 'Role added to group', { groupId, roleName });
            return result;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to add role to group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async removeRoleFromGroup(groupId: string, roleName: string): Promise<any> {
        try {
            const result = await this.keycloakService.removeRoleFromGroup(groupId, roleName);
            this.loggerService.logAction('REMOVE_ROLE_FROM_GROUP', 'Role removed from group', { groupId, roleName });
            return result;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to remove role from group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getGroupRoles(groupId: string): Promise<any> {
        try {
            const roles = await this.keycloakService.getGroupRoles(groupId);
            this.loggerService.logAction('GET_GROUP_ROLES', 'Fetched group roles', { groupId, returnedData: roles });
            return roles;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch group roles', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async addUserToGroup(userId: string, groupId: string): Promise<void> {
        const dbUser = await this.databaseService.findUserById(userId);
        console.log('User:', dbUser);

        if (!dbUser) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        try {
            await this.keycloakService.addUserToGroup(dbUser.keycloakId, groupId);
            this.loggerService.logAction('ADD_USER_TO_GROUP', 'User added to group', { userId, groupId });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to add user to group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async removeUserFromGroup(userId: string, groupId: string): Promise<void> {
        const dbUser = await this.databaseService.findUserById(userId);
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        try {
            await this.keycloakService.removeUserFromGroup(dbUser.keycloakId, groupId);
            this.loggerService.logAction('REMOVE_USER_FROM_GROUP', 'User removed from group', { userId, groupId });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to remove user from group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getAllUsersFromGroup(groupId: string): Promise<any[]> {
        try {
            const users = await this.keycloakService.getAllUsersFromGroup(groupId);
            this.loggerService.logAction('GET_ALL_USERS_FROM_GROUP', 'Fetched all users from group', { groupId, returnedData: users });
            return users;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch users from group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getGroupById(groupId: string): Promise<any> {
        try {
            const group = await this.keycloakService.getGroupById(groupId);
            this.loggerService.logAction('GET_GROUP_BY_ID', 'Fetched group by ID', { groupId, returnedData: group });
            return group;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch group by ID', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getGroupByName(groupName: string): Promise<any> {
        try {
            const group = await this.keycloakService.getGroupByName(groupName);
            this.loggerService.logAction('GET_GROUP_BY_NAME', 'Fetched group by name', { groupName, returnedData: group });
            return group;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch group by name', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getUserGroups(userId: string): Promise<any[]> {
        const dbUser = await this.databaseService.findUserById(userId);
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        try {
            const groups = await this.keycloakService.getUserGroups(dbUser.keycloakId);
            this.loggerService.logAction('GET_USER_GROUPS', 'Fetched user groups', { userId, returnedData: groups });
            return groups;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch user groups', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }



  // ==============================
  // Client Role Management Endpoints
  // ==============================




    async createClientRole(roleName: string, description: string): Promise<void> {
        try {
            await this.keycloakService.createClientRole(roleName, description);
            this.loggerService.logAction('CREATE_CLIENT_ROLE', 'Client role created successfully', { roleName, description });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to create client role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async updateClientRole(roleName: string, newName?: string, newDescription?: string): Promise<void> {
        try {
            await this.keycloakService.updateClientRole(roleName, newName, newDescription);
            this.loggerService.logAction('UPDATE_CLIENT_ROLE', 'Client role updated successfully', { roleName, newName, newDescription });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to update client role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getAllClientRoles(): Promise<any[]> {
        try {
            const roles = await this.keycloakService.getAllClientRoles();
            this.loggerService.logAction('GET_ALL_CLIENT_ROLES', 'Fetched all client roles', { returnedData: roles });
            return roles;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch client roles', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async deleteClientRole(roleName: string): Promise<void> {
        try {
            await this.keycloakService.deleteClientRole(roleName);
            this.loggerService.logAction('DELETE_CLIENT_ROLE', 'Client role deleted successfully', { roleName });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to delete client role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async addClientRoleToGroup(groupId: string, roleName: string): Promise<void> {
        try {
            await this.keycloakService.addClientRoleToGroup(groupId, roleName);
            this.loggerService.logAction('ADD_CLIENT_ROLE_TO_GROUP', 'Client role added to group', { groupId, roleName });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to add client role to group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async removeClientRoleFromGroup(groupId: string, roleName: string): Promise<void> {
        try {
            await this.keycloakService.removeClientRoleFromGroup(groupId, roleName);
            this.loggerService.logAction('REMOVE_CLIENT_ROLE_FROM_GROUP', 'Client role removed from group', { groupId, roleName });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to remove client role from group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async addClientRoleToUser(userId: string, roleName: string): Promise<void> {
        const dbUser = await this.databaseService.findUserById(userId);
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        try {
            await this.keycloakService.addClientRoleToUser(dbUser.keycloakId, roleName);
            this.loggerService.logAction('ADD_CLIENT_ROLE_TO_USER', 'Client role added to user', { userId, roleName });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to add client role to user', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async removeClientRoleFromUser(userId: string, roleName: string): Promise<void> {
        const dbUser = await this.databaseService.findUserById(userId);
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        try {
            await this.keycloakService.removeClientRoleFromUser(dbUser.keycloakId, roleName);
            this.loggerService.logAction('REMOVE_CLIENT_ROLE_FROM_USER', 'Client role removed from user', { userId, roleName });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to remove client role from user', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async findUsersByClientRole(roleName: string): Promise<any[]> {
        try {
            const users = await this.keycloakService.findUsersByClientRole(roleName);
            this.loggerService.logAction('FIND_USERS_BY_CLIENT_ROLE', 'Fetched users by client role', { roleName, returnedData: users });
            return users;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch users by client role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async findClientRolesByUserId(userId: string): Promise<any[]> {
        const dbUser = await this.databaseService.findUserById(userId);
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        try {
            const roles = await this.keycloakService.findClientRolesByUserId(dbUser.keycloakId);
            this.loggerService.logAction('FIND_CLIENT_ROLES_BY_USER_ID', 'Fetched client roles by user ID', { userId, returnedData: roles });
            return roles;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch client roles by user ID', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }



    // ==============================
    // Client Management Endpoints
    // ==============================


    
    async createClient(clientData: any): Promise<any> {
        try {
            const createdClient = await this.keycloakService.createClient(clientData);
            this.loggerService.logAction('CREATE_CLIENT', 'Client created successfully', { clientData });
            return createdClient;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to create client', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async deleteClient(clientId: string): Promise<void> {
        try {
            await this.keycloakService.deleteClient(clientId);
            this.loggerService.logAction('DELETE_CLIENT', 'Client deleted successfully', { clientId });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to delete client', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async updateClient(clientId: string, clientData: any): Promise<any> {
        try {
            const updatedClient = await this.keycloakService.updateClient(clientId, clientData);
            this.loggerService.logAction('UPDATE_CLIENT', 'Client updated successfully', { clientId, clientData });
            return updatedClient;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to update client', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getClientByName(clientName: string): Promise<any> {
        try {
            const client = await this.keycloakService.getClientByName(clientName);
            this.loggerService.logAction('GET_CLIENT_BY_NAME', 'Fetched client by name', { clientName, returnedData: client });
            return client;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch client by name', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getClientById(clientId: string): Promise<any> {
        try {
            const client = await this.keycloakService.getClientById(clientId);
            this.loggerService.logAction('GET_CLIENT_BY_ID', 'Fetched client by ID', { clientId, returnedData: client });
            return client;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch client by ID', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getAllClients(): Promise<any[]> {
        try {
            const clients = await this.keycloakService.getAllClients();
            this.loggerService.logAction('GET_ALL_CLIENTS', 'Fetched all clients', { returnedData: clients });
            return clients;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch all clients', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async addClientRole(clientId: string, roleName: string, description: string): Promise<void> {
        try {
            await this.keycloakService.addClientRole(clientId, roleName, description);
            this.loggerService.logAction('ADD_CLIENT_ROLE', 'Client role added successfully', { clientId, roleName, description });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to add client role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async removeClientRole(clientId: string, roleName: string): Promise<void> {
        try {
            await this.keycloakService.removeClientRole(clientId, roleName);
            this.loggerService.logAction('REMOVE_CLIENT_ROLE', 'Client role removed successfully', { clientId, roleName });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to remove client role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async regenerateClientSecret(clientId: string): Promise<any> {
        try {
            const newSecret = await this.keycloakService.regenerateClientSecret(clientId);
            this.loggerService.logAction('REGENERATE_CLIENT_SECRET', 'Client secret regenerated successfully', { clientId, newSecret });
            return newSecret;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to regenerate client secret', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}