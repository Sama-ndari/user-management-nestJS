//src/users/transactions/transactions.service.ts
import { HttpException, HttpStatus, Injectable, NotFoundException } from '@nestjs/common';
import { KeycloakService } from '../keycloak/keycloak.service';
import { CreateUserDatabaseDto, CreateUserDto, GoogleAuthDto, SearchUserDto, UserRepresentation } from '../users/dto/create-user.dto';
import { DatabaseService } from '../database/database.service';
import { Connection } from 'mongoose';
import { InjectConnection } from '@nestjs/mongoose';
import { LoginDto } from 'src/users/dto/login.dto';
import { LogoutDto } from 'src/users/dto/logout.dto';
import { PageDto } from 'src/common/page-dto/page-dto';
import { PageOptionsDto } from 'src/common/page-options-dto/page-options-dto';
import { LoggerService } from '../keycloak/security/logger.service';
import { UserActions } from '../users/entities/enumerate.entity';
import { CommonHelpers } from 'src/common/helpers';

@Injectable()
export class TransactionsService {
    constructor(
        private keycloakService: KeycloakService,
        private databaseService: DatabaseService,
        @InjectConnection() private readonly connection: Connection,
        private readonly loggerService: LoggerService,
    ) {
        CommonHelpers.initializeRedisClient();
    }



    // ==============================
    // Miscellaneous Endpoints
    // ==============================



    async getAuditLogs(filters: { date?: string; actor?: string; action?: string; startTime?: string; endTime?: string; }): Promise<any> {
        const logs = await CommonHelpers.retry(
            () => this.keycloakService.getAuditLogsDB({
                date: filters.date ?? undefined,
                actor: filters.actor ?? undefined,
                action: filters.action ?? undefined,
                startTime: filters.startTime ?? undefined,
                endTime: filters.endTime ?? undefined
            }),
        );
        return logs;
    }

    async deleteAuditLogs(
        filters: {
            date?: string;
            actor?: string;
            action?: string;
            startTime?: string;
            endTime?: string;
        }): Promise<{ deletedCount: number }> {
        const logs = await this.keycloakService.deleteAuditLogs({ date: filters.date ?? undefined, actor: filters.actor ?? undefined, action: filters.action ?? undefined, startTime: filters.startTime ?? undefined, endTime: filters.endTime ?? undefined });
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


    // Cache key generation methods
    private getUserCacheKey(id: string): string {
        return `user:${id}`;
    }

    private getUserByUsernameCacheKey(username: string): string {
        return `user:username:${username}`;
    }

    private getUserByEmailCacheKey(email: string): string {
        return `user:email:${email}`;
    }

    private getUsersListCacheKey(pageOptions: PageOptionsDto, searchUser: SearchUserDto): string {
        return `users:all:${JSON.stringify(pageOptions)}:${JSON.stringify(searchUser)}`;
    }

    private getUsersByStatusCacheKey(status: string, pageOptions: PageOptionsDto): string {
        return `users:status:${status}:${JSON.stringify(pageOptions)}`;
    }

    private getConnectedUsersCacheKey(): string {
        return 'users:connected';
    }

    private async invalidateUserCaches(
        userId: string,
        username: string,
        email: string,
        status: string
    ): Promise<void> {
        const keysToInvalidate = [
            this.getUserCacheKey(userId),
            this.getUserByUsernameCacheKey(username),
            this.getUserByEmailCacheKey(email),
            this.getUsersListCacheKey(new PageOptionsDto(), new SearchUserDto()),
            this.getUsersByStatusCacheKey(status, new PageOptionsDto()),
            this.getConnectedUsersCacheKey(),
        ];

        await CommonHelpers.invalidateCache(keysToInvalidate);

    }

    private async invalidateUserCacheByPattern(): Promise<void> {
        await CommonHelpers.invalidateCacheByPattern('user*');
        await CommonHelpers.invalidateCacheByPattern('users*');
    }




    async login(userDto: LoginDto): Promise<any> {
        return CommonHelpers.retry(async () => {
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
        });
    }

    async decodeToken(token: string): Promise<any> {
        try {
            const decodedData = await CommonHelpers.retry(() => this.keycloakService.decodeJwt(token));
            this.loggerService.logAction('DECODE_TOKEN', 'Decoding JWT token', { decodedData });
            return decodedData;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to decode token', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async refreshAccessToken(token: string): Promise<any> {
        try {
            const refreshedToken = await CommonHelpers.retry(() => this.keycloakService.refreshAccessToken(token));
            this.loggerService.logAction('REFRESH_ACCESS_TOKEN', 'Refreshing access token', { tokenRefreshed: !!refreshedToken });
            return refreshedToken;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to refresh token', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async logout(token: string): Promise<any> {
        try {
            const logoutResponse = await CommonHelpers.retry(() => this.keycloakService.logout(token));
            this.loggerService.logAction('USER_LOGOUT', 'User logout attempt', { tokenInvalidated: logoutResponse });
            return logoutResponse;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to logout', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async createUserWithGoogle(googleAuthDto: GoogleAuthDto): Promise<any> {
        const session = await this.connection.startSession();
        session.startTransaction();

        try {
            const keycloakUser = await CommonHelpers.retry(() => this.keycloakService.authenticateWithGoogle(googleAuthDto));
            let dbUser = await CommonHelpers.retry(() => this.databaseService.findUserByKeycloakId(keycloakUser.id));

            if (!dbUser) {
                const userForDB = {
                    keycloakId: keycloakUser.id,
                    username: keycloakUser.username,
                    email: keycloakUser.email,
                    firstName: keycloakUser.firstName || googleAuthDto.firstName,
                    lastName: keycloakUser.lastName || googleAuthDto.lastName,
                    phone: googleAuthDto.phone,
                    address: googleAuthDto.address,
                    logo: keycloakUser.attributes?.picture?.[0] || googleAuthDto.picture,
                    status: 'active',
                };

                dbUser = await CommonHelpers.retry(() => this.databaseService.createUser(userForDB, session));
            }

            await session.commitTransaction();
            session.endSession();

            const logData = {
                username: dbUser.username,
                email: dbUser.email,
                keycloakId: dbUser.keycloakId,
                status: dbUser.status,
                authMethod: 'google'
            };
            this.loggerService.logAction('CREATE_USER_GOOGLE', 'User created/authenticated via Google', logData);

            // Invalidate all relevant caches
            await CommonHelpers.invalidateCache([
                this.getUserCacheKey(dbUser._id),
                this.getUserByUsernameCacheKey(dbUser.username),
                this.getUserByEmailCacheKey(dbUser.email),
                this.getUsersListCacheKey(new PageOptionsDto(), new SearchUserDto()),
                this.getUsersByStatusCacheKey(dbUser.status, new PageOptionsDto()),
                this.getConnectedUsersCacheKey(),
            ]);

            return {
                message: 'Google authentication successful',
                user: dbUser,
            };
        } catch (error) {
            await session.abortTransaction();
            session.endSession();
            throw new HttpException(
                error.message || 'Failed to create user with Google account',
                HttpStatus.INTERNAL_SERVER_ERROR
            );
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

            const createdKeycloakUser = await CommonHelpers.retry(() => this.keycloakService.createUser(keycloakUserPayload));
            keycloakId = createdKeycloakUser.id;

            const userForDB = { ...userDto, keycloakId: createdKeycloakUser.id };
            const createdUser = await CommonHelpers.retry(() => this.databaseService.createUser(userForDB, session));

            await session.commitTransaction();
            session.endSession();

            const logData = {
                username: createdUser.username,
                email: createdUser.email,
                keycloakId: createdUser.keycloakId,
                status: createdUser.status,
            };
            this.loggerService.logAction('CREATE_USER', 'User created successfully', logData);

            // Invalidate all relevant caches
            await this.invalidateUserCaches(
                createdUser._id,
                createdUser.username,
                createdUser.email,
                createdUser.status
            );

            return {
                message: 'User created successfully! Please check your email to verify your account.',
                user: createdUser,
                emailSent: createdKeycloakUser.emailVerified ? true : false,
            };
        } catch (error) {
            await session.abortTransaction();
            session.endSession();

            if (keycloakId) {
                try {
                    await CommonHelpers.retry(() => this.keycloakService.deleteUser(keycloakId));
                } catch (compensationError) {
                    console.error('Compensation error:', compensationError.message);
                }
            }

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

            const createdKeycloakUser = await CommonHelpers.retry(() => this.keycloakService.createUserWithoutRoles(keycloakUserPayload));
            keycloakId = createdKeycloakUser.id;

            const userForDB = { ...userDto, keycloakId: createdKeycloakUser.id };
            const createdUser = await CommonHelpers.retry(() => this.databaseService.createUser(userForDB, session));

            await session.commitTransaction();
            session.endSession();

            const logData = {
                username: createdUser.username,
                email: createdUser.email,
                keycloakId: createdUser.keycloakId,
                status: createdUser.status,
            };
            this.loggerService.logAction('CREATE_USER_WITHOUT_ROLES', 'User created successfully without roles', logData);

            // Invalidate all relevant caches
            await this.invalidateUserCaches(
                createdUser._id,
                createdUser.username,
                createdUser.email,
                createdUser.status
            );

            return {
                message: 'User created successfully! Please check your email to verify your account.',
                user: createdUser,
                emailSent: createdKeycloakUser.emailVerified ? true : false,
            };
        } catch (error) {
            await session.abortTransaction();
            session.endSession();

            if (keycloakId) {
                try {
                    await CommonHelpers.retry(() => this.keycloakService.deleteUser(keycloakId));
                } catch (compensationError) {
                    console.error('Compensation error:', compensationError.message);
                }
            }

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
        const dbUser = await CommonHelpers.retry(() => this.databaseService.findUserById(id));
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }

        const keycloakId = dbUser.keycloakId;
        const keycloakOGUser = await CommonHelpers.retry(() => this.keycloakService.findUserById(keycloakId));

        const session = await this.connection.startSession();
        session.startTransaction();

        try {
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

            await CommonHelpers.retry(() => this.keycloakService.updateUser(keycloakId, keycloakUserPayload));
            const userForDB = { ...userDto, keycloakId: keycloakId };
            const updatedUser = await CommonHelpers.retry(() => this.databaseService.updateUser(id, userForDB, session));

            await session.commitTransaction();
            session.endSession();

            const mergedUser: UserRepresentation = {
                ...dbUser,
                ...keycloakUserPayload,
            };
            this.loggerService.logAction('UPDATE_USER', 'User updated successfully', { updatedData: mergedUser });

            // Invalidate all relevant caches
            const invalidationKeys = [
                this.getUserCacheKey(id),
                this.getUserByUsernameCacheKey(dbUser.username),
                this.getUserByEmailCacheKey(dbUser.email),
                this.getUsersListCacheKey(new PageOptionsDto(), new SearchUserDto()),
                this.getUsersByStatusCacheKey(dbUser.status, new PageOptionsDto()),
                this.getConnectedUsersCacheKey(),
            ];
            if (userDto.username && userDto.username !== dbUser.username) {
                invalidationKeys.push(this.getUserByUsernameCacheKey(userDto.username));
            }
            if (userDto.email && userDto.email !== dbUser.email) {
                invalidationKeys.push(this.getUserByEmailCacheKey(userDto.email));
            }
            if (userDto.status && userDto.status !== dbUser.status) {
                invalidationKeys.push(this.getUsersByStatusCacheKey(userDto.status, new PageOptionsDto()));
            }
            await CommonHelpers.invalidateCache(invalidationKeys);

            return updatedUser;
        } catch (error) {
            await session.abortTransaction();
            session.endSession();

            if (error && keycloakOGUser) {
                try {
                    await CommonHelpers.retry(() => this.keycloakService.updateUser(keycloakId, keycloakOGUser));
                    console.error('Error occurred, consider reverting Keycloak changes if necessary.');
                } catch (compensationError) {
                    console.error('Compensation error:', compensationError.message);
                }
            }
            throw new HttpException(error.message || 'Failed to update user transactionally', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    async resetPassword(id: string, newPassword: string): Promise<any> {
        const dbUser = await CommonHelpers.retry(() => this.databaseService.findUserById(id));
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }

        const keycloakId = dbUser.keycloakId;
        const resetResponse = await CommonHelpers.retry(() => this.keycloakService.resetPassword(keycloakId, newPassword));

        this.loggerService.logAction('RESET_PASSWORD', 'Password reset successfully', {
            userId: id,
            keycloakId: keycloakId,
            resetStatus: resetResponse ? 'Success' : 'Failed',
        });

        await CommonHelpers.invalidateCache([this.getUserCacheKey(id)]);

        return resetResponse;
    }

    async generateNewPassword(identifier: string): Promise<any> {
        try {
            const keycloakResponse = await CommonHelpers.retry(() => this.keycloakService.generateNewPassword(identifier));
            if (!keycloakResponse) {
                throw new HttpException('Error while generating new password', HttpStatus.NOT_FOUND);
            }
            this.loggerService.logAction('GENERATING-NEW-PASSWORD', 'New User credentials', keycloakResponse);
            console.log("New password: ", keycloakResponse);

            // Invalidate caches if identifier is an ID
            if (identifier.length === 36) { // Assuming UUID length
                await CommonHelpers.invalidateCache([this.getUserCacheKey(identifier)]);
            }

            return keycloakResponse;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to update user password', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async findUserById(id: string): Promise<any> {
        const cacheKey = this.getUserCacheKey(id);
        return CommonHelpers.cacheOrFetch(
            cacheKey,
            async () => {
                let keycloakUser: any, dbUser: any;

                try {
                    dbUser = await CommonHelpers.retry(() => this.databaseService.findUserById(id));
                } catch (error) {
                    console.error('Database fetch error:', error.message);
                    throw new NotFoundException(`User with id ${id} not found in both systems.`);
                }

                try {
                    keycloakUser = await CommonHelpers.retry(() => this.keycloakService.findUserById(dbUser.keycloakId));
                } catch (error) {
                    console.error('Keycloak fetch error:', error.message);
                }

                console.log('Database user:', dbUser);
                console.log('Keycloak user:', keycloakUser);
                const mergedUser: UserRepresentation = {
                    ...dbUser,
                    ...keycloakUser,
                };

                this.loggerService.logAction('FIND_USER_BY_ID', "Fetching user by ID", { returnedData: mergedUser });

                return mergedUser;
            },
            CommonHelpers.DEFAULT_TTL,
            'user-details'
        );
    }

    async findUserByUsername(username: string): Promise<any> {
        const cacheKey = this.getUserByUsernameCacheKey(username);
        return CommonHelpers.cacheOrFetch(
            cacheKey,
            async () => {
                let keycloakUser: any, dbUser: any;

                try {
                    dbUser = await CommonHelpers.retry(() => this.databaseService.findUserByUsername(username));
                } catch (error) {
                    console.error('Database fetch error:', error.message);
                    throw new NotFoundException(`User with username ${username} not found in both systems.`);
                }

                try {
                    keycloakUser = await CommonHelpers.retry(() => this.keycloakService.findUserByUsername(username));
                } catch (error) {
                    console.error('Keycloak fetch error:', error.message);
                }

                console.log('Database user:', dbUser);
                console.log('Keycloak user:', keycloakUser);
                const mergedUser: UserRepresentation = {
                    ...dbUser,
                    ...keycloakUser,
                };

                this.loggerService.logAction('FIND_USER_BY_USERNAME', "Fetching user by username", { returnedData: mergedUser });

                return mergedUser;
            },
            CommonHelpers.DEFAULT_TTL,
            'user-details'
        );
    }

    async getConnectedUsers(): Promise<any[]> {
        const cacheKey = this.getConnectedUsersCacheKey();
        return CommonHelpers.cacheOrFetch(
            cacheKey,
            async () => {
                const connectedUsers = await CommonHelpers.retry(() => this.keycloakService.getConnectedUsers());
                this.loggerService.logAction('GET_CONNECTED_USERS', "Fetching connected users", { returnedData: connectedUsers });
                return connectedUsers;
            },
            CommonHelpers.DEFAULT_TTL,
            'user-lists'
        );
    }

    async findAllUsers(pageOptionsDto: PageOptionsDto, searchUserDto: SearchUserDto): Promise<PageDto<any>> {
        const cacheKey = this.getUsersListCacheKey(pageOptionsDto, searchUserDto);
        return CommonHelpers.cacheOrFetch(
            cacheKey,
            async () => {
                let keycloakUsers: any[] = [];
                let dbUsers;

                try {
                    dbUsers = await CommonHelpers.retry(() => this.databaseService.findAllUsers(pageOptionsDto, searchUserDto));
                } catch (error) {
                    console.error('Database fetch error:', error.message);
                    throw new NotFoundException('Users not found in the database.');
                }

                try {
                    keycloakUsers = await CommonHelpers.retry(() => this.keycloakService.findAllUsers());
                } catch (error) {
                    console.error('Keycloak fetch error:', error.message);
                }

                console.log('Database users:', dbUsers.data);
                console.log('Keycloak users:', keycloakUsers);
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
            },
            CommonHelpers.DEFAULT_TTL,
            'user-lists'
        );
    }

    async findAllUsersByStatus(status: string, pageOptionsDto: PageOptionsDto): Promise<PageDto<CreateUserDatabaseDto>> {
        const cacheKey = this.getUsersByStatusCacheKey(status, pageOptionsDto);
        return CommonHelpers.cacheOrFetch(
            cacheKey,
            async () => {
                let keycloakUsers: any[] = [];
                let dbUsers;

                try {
                    dbUsers = await CommonHelpers.retry(() => this.databaseService.findAllUsersByStatus(status, pageOptionsDto));
                } catch (error) {
                    console.error('Database fetch error:', error.message);
                    throw new NotFoundException('Users not found in the database.');
                }

                try {
                    keycloakUsers = await CommonHelpers.retry(() => this.keycloakService.findAllUsers());
                } catch (error) {
                    console.error('Keycloak fetch error:', error.message);
                }

                const mergedUsers: CreateUserDatabaseDto[] = dbUsers.data.map(dbUser => {
                    const keycloakUser = keycloakUsers.find(kcUser => kcUser.id === dbUser.keycloakId);
                    return {
                        ...dbUser,
                        ...keycloakUser,
                    };
                });

                this.loggerService.logAction('LIST_USERS_BY_STATUS', `Getting all Users by status: ${status}`, { returnedData: mergedUsers });
                return new PageDto(mergedUsers, dbUsers.meta);
            },
            CommonHelpers.DEFAULT_TTL,
            'user-lists'
        );
    }

    async findUserByEmail(email: string): Promise<any> {
        const cacheKey = this.getUserByEmailCacheKey(email);
        return CommonHelpers.cacheOrFetch(
            cacheKey,
            async () => {
                let keycloakUser: any, dbUser: any;

                try {
                    dbUser = await CommonHelpers.retry(() => this.databaseService.findUserByEmail(email));
                } catch (error) {
                    console.error('Database fetch error:', error.message);
                    throw new NotFoundException(`User with email ${email} not found in both systems.`);
                }

                try {
                    keycloakUser = await CommonHelpers.retry(() => this.keycloakService.findUserByEmail(email));
                } catch (error) {
                    console.error('Keycloak fetch error:', error.message);
                }

                console.log('Database user:', dbUser);
                console.log('Keycloak user:', keycloakUser);
                const mergedUser: UserRepresentation = {
                    ...dbUser,
                    ...keycloakUser,
                };

                this.loggerService.logAction('FIND_USER_BY_EMAIL', "Fetching user by email", { returnedData: mergedUser });

                return mergedUser;
            },
            CommonHelpers.DEFAULT_TTL,
            'user-details'
        );
    }


    // async findAllUsers(pageOptionsDto: PageOptionsDto): Promise<PageDto<CreateUserDatabaseDto>> {
    //     let keycloakUsers: any[] = [];
    //     let dbUsers;

    //     try {
    //         dbUsers = await CommonHelpers.retry(() => this.databaseService.findAllUsers(pageOptionsDto));
    //     } catch (error) {
    //         console.error('Database fetch error:', error.message);
    //         throw new NotFoundException('Users not found in the database.');
    //     }

    //     try {
    //         keycloakUsers = await CommonHelpers.retry(() => this.keycloakService.findAllUsers());
    //     } catch (error) {
    //         // Log error but allow fallback
    //         console.error('Keycloak fetch error:', error.message);
    //     }

    //     console.log('Database users:', dbUsers.data);
    //     console.log('Keycloak users:', keycloakUsers);
    //     // Merge users from both sources, prioritizing Keycloak values if available
    //     const mergedUsers: CreateUserDatabaseDto[] = dbUsers.data.map(dbUser => {
    //         const keycloakUser = keycloakUsers.find(kcUser => kcUser.id === dbUser.keycloakId);
    //         return {
    //             ...dbUser,
    //             ...keycloakUser,
    //         };
    //     });
    //     console.log('Merged users:', mergedUsers);
    //     this.loggerService.logAction('LIST_USERS', "Getting all Users", { returnedData: mergedUsers });
    //     return new PageDto(mergedUsers, dbUsers.meta);
    // }

    async deleteUser(id: string): Promise<any> {
        const session = await this.connection.startSession();
        session.startTransaction();

        try {
            const dbUser = await CommonHelpers.retry(() => this.databaseService.findUserById(id));
            if (!dbUser || !dbUser.keycloakId) {
                throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
            }

            const keycloakId = dbUser.keycloakId;
            const deletedUserDB = await CommonHelpers.retry(() => this.databaseService.deleteUser(id, session));
            console.log('Database user deleted');

            await CommonHelpers.retry(() => this.keycloakService.deleteUser(keycloakId));
            console.log('Keycloak user deleted');

            await session.commitTransaction();
            session.endSession();

            this.loggerService.logAction('DELETE_USER', "User deleted successfully", { userId: id, keycloakId });

            // Invalidate all relevant caches
            await this.invalidateUserCaches(
                id,
                dbUser.username,
                dbUser.email,
                dbUser.status
            );

            return deletedUserDB;
        } catch (error) {
            await session.abortTransaction();
            session.endSession();
            console.error('Error occurred during user deletion:', error.message);
            throw new HttpException(error.message || 'Failed to delete user transactionally', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }



    // ==============================
    // Realm Role Management Endpoints
    // ==============================




    async createRealmRole(roleName: string, description: string): Promise<any> {
        try {
            const createdRole = await CommonHelpers.retry(() => this.keycloakService.createRealmRole(roleName, description));
            this.loggerService.logAction('CREATE_ROLE', 'Role created successfully', { roleName, description });
            return createdRole;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to create role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async deleteRealmRole(roleName: string): Promise<any> {
        try {
            await CommonHelpers.retry(() => this.keycloakService.deleteRealmRole(roleName));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('DELETE_ROLE', 'Role deleted successfully', { roleName });
            return { message: `Role ${roleName} deleted successfully` };
        } catch (error) {
            throw new HttpException(error.message || 'Failed to delete role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async updateRealmRole(roleName: string, newName?: string, newDescription?: string): Promise<any> {
        try {
            const updatedRole = await CommonHelpers.retry(() => this.keycloakService.updateRealmRole(roleName, newName, newDescription));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('UPDATE_ROLE', 'Role updated successfully', { roleName, newName, newDescription });
            return updatedRole;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to update role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async assignRealmRole(userId: string, roleName: string): Promise<void> {
        const dbUser = await CommonHelpers.retry(() => this.databaseService.findUserById(userId));
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        await CommonHelpers.retry(() => this.keycloakService.assignRealmRole(dbUser.keycloakId, roleName));
        await this.invalidateUserCacheByPattern();
        this.loggerService.logAction('ASSIGN_ROLE', 'Role assigned to user', { userId, roleName });
    }

    async deAssignRealmRole(userId: string, roleName: string): Promise<void> {
        const dbUser = await CommonHelpers.retry(() => this.databaseService.findUserById(userId));
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        await CommonHelpers.retry(() => this.keycloakService.deAssignRealmRole(dbUser.keycloakId, roleName));
        await this.invalidateUserCacheByPattern();
        this.loggerService.logAction('DE_ASSIGN_ROLE', 'Role de-assigned from user', { userId, roleName });
    }

    async getAllRealmRoles(): Promise<any[]> {
        try {
            const roles = await CommonHelpers.retry(() => this.keycloakService.getAllRealmRoles());
            this.loggerService.logAction('GET_ALL_ROLES', 'Fetched all roles', { returnedData: roles });
            return roles;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch roles', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async findAllUsersByRealmRole(roleName: string): Promise<any[]> {
        let keycloakUsers: UserRepresentation[] = [];

        try {
            keycloakUsers = await CommonHelpers.retry(() => this.keycloakService.findAllUsersByRealmRole(roleName));
            console.log('Keycloak users:', keycloakUsers);
        } catch (error) {
            console.error('Keycloak fetch error:', error.message);
        }
        this.loggerService.logAction('LIST_USERS_BY_ROLE', `Getting all Users by Role: {roleName}`, { roleName, returnedData: keycloakUsers });
        return keycloakUsers;
    }

    async getUserRealmRoles(userId: string): Promise<any[]> {
        const dbUser = await CommonHelpers.retry(() => this.databaseService.findUserById(userId));
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        try {
            const roles = await CommonHelpers.retry(() => this.keycloakService.getUserRealmRole(dbUser.keycloakId));
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
            const createdGroup = await CommonHelpers.retry(() => this.keycloakService.createGroup(groupName, attributes));
            this.loggerService.logAction('CREATE_GROUP', 'Group created successfully', { groupName, attributes });
            return createdGroup;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to create group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async updateGroup(groupId: string, groupName?: string, attributes?: Record<string, any>): Promise<any> {
        try {
            const updatedGroup = await CommonHelpers.retry(() => this.keycloakService.updateGroup(groupId, groupName, attributes));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('UPDATE_GROUP', 'Group updated successfully', { groupId, groupName, attributes });
            return updatedGroup;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to update group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async deleteGroup(groupId: string): Promise<any> {
        try {
            const deletedGroup = await CommonHelpers.retry(() => this.keycloakService.deleteGroup(groupId));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('DELETE_GROUP', 'Group deleted successfully', { groupId });
            return deletedGroup;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to delete group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getAllGroups(): Promise<any[]> {
        try {
            const groups = await CommonHelpers.retry(() => this.keycloakService.getAllGroups());
            this.loggerService.logAction('GET_ALL_GROUPS', 'Fetched all groups', { returnedData: groups });
            return groups;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch groups', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async addRoleToGroup(groupId: string, roleName: string): Promise<any> {
        try {
            const result = await CommonHelpers.retry(() => this.keycloakService.addRoleToGroup(groupId, roleName));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('ADD_ROLE_TO_GROUP', 'Role added to group', { groupId, roleName });
            return result;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to add role to group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async removeRoleFromGroup(groupId: string, roleName: string): Promise<any> {
        try {
            const result = await CommonHelpers.retry(() => this.keycloakService.removeRoleFromGroup(groupId, roleName));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('REMOVE_ROLE_FROM_GROUP', 'Role removed from group', { groupId, roleName });
            return result;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to remove role from group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getGroupRoles(groupId: string): Promise<any> {
        try {
            const roles = await CommonHelpers.retry(() => this.keycloakService.getGroupRoles(groupId));
            this.loggerService.logAction('GET_GROUP_ROLES', 'Fetched group roles', { groupId, returnedData: roles });
            return roles;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch group roles', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async addUserToGroup(userId: string, groupId: string): Promise<void> {
        const dbUser = await CommonHelpers.retry(() => this.databaseService.findUserById(userId));
        console.log('User:', dbUser);

        if (!dbUser) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        try {
            await CommonHelpers.retry(() => this.keycloakService.addUserToGroup(dbUser.keycloakId, groupId));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('ADD_USER_TO_GROUP', 'User added to group', { userId, groupId });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to add user to group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async removeUserFromGroup(userId: string, groupId: string): Promise<void> {
        const dbUser = await CommonHelpers.retry(() => this.databaseService.findUserById(userId));
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        try {
            await CommonHelpers.retry(() => this.keycloakService.removeUserFromGroup(dbUser.keycloakId, groupId));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('REMOVE_USER_FROM_GROUP', 'User removed from group', { userId, groupId });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to remove user from group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getAllUsersFromGroup(groupId: string): Promise<any[]> {
        try {
            const users = await CommonHelpers.retry(() => this.keycloakService.getAllUsersFromGroup(groupId));
            // For each user, try to find the corresponding DB user and add its _id
            const usersWithDbId = await Promise.all(users.map(async (user: any) => {
                let dbUser: any = null;
                try {
                    dbUser = await CommonHelpers.retry(() => this.databaseService.findUserByKeycloakId(user.id));
                } catch (e) {
                    // Ignore if not found
                }
                return {
                    ...user,
                    dbId: dbUser ? dbUser._id : null,
                };
            }));
            this.loggerService.logAction('GET_ALL_USERS_FROM_GROUP', 'Fetched all users from group', { groupId, returnedData: usersWithDbId });
            return usersWithDbId;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch users from group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getAllUsersFromNameGroup(groupName: string): Promise<any[]> {
        try {
            const users = await CommonHelpers.retry(() => this.keycloakService.getAllUsersFromNameGroup(groupName));
            // For each user, try to find the corresponding DB user and add its _id
            const usersWithDbId = await Promise.all(users.map(async (user: any) => {
                let dbUser:any = null;
                try {
                    dbUser = await CommonHelpers.retry(() => this.databaseService.findUserByKeycloakId(user.id));
                } catch (e) {
                    // Ignore if not found
                }
                return {
                    ...user,
                    dbId: dbUser ? dbUser._id : null,
                };
            }));
            this.loggerService.logAction('GET_ALL_USERS_FROM_NAME_GROUP', 'Fetched all users from group by name', { groupName, returnedData: usersWithDbId });
            return usersWithDbId;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch users from group by name', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getGroupById(groupId: string): Promise<any> {
        try {
            const group = await CommonHelpers.retry(() => this.keycloakService.getGroupById(groupId));
            this.loggerService.logAction('GET_GROUP_BY_ID', 'Fetched group by ID', { groupId, returnedData: group });
            return group;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch group by ID', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getGroupByName(groupName: string): Promise<any> {
        try {
            const group = await CommonHelpers.retry(() => this.keycloakService.getGroupByName(groupName));
            this.loggerService.logAction('GET_GROUP_BY_NAME', 'Fetched group by name', { groupName, returnedData: group });
            return group;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch group by name', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getUserGroups(userId: string): Promise<any[]> {
        const dbUser = await CommonHelpers.retry(() => this.databaseService.findUserById(userId));
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        try {
            const groups = await CommonHelpers.retry(() => this.keycloakService.getUserGroups(dbUser.keycloakId));
            this.loggerService.logAction('GET_USER_GROUPS', 'Fetched user groups', { userId, returnedData: groups });
            return groups;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch user groups', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }




    // ==============================
    // ClientRole Management Endpoints
    // ==============================

    async createClientRole(roleName: string, description: string): Promise<void> {
        try {
            await CommonHelpers.retry(() => this.keycloakService.createClientRole(roleName, description));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('CREATE_CLIENT_ROLE', 'Client role created successfully', { roleName, description });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to create client role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async updateClientRole(roleName: string, newName?: string, newDescription?: string): Promise<void> {
        try {
            await CommonHelpers.retry(() => this.keycloakService.updateClientRole(roleName, newName, newDescription));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('UPDATE_CLIENT_ROLE', 'Client role updated successfully', { roleName, newName, newDescription });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to update client role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getAllClientRoles(): Promise<any[]> {
        try {
            const roles = await CommonHelpers.retry(() => this.keycloakService.getAllClientRoles());
            this.loggerService.logAction('GET_ALL_CLIENT_ROLES', 'Fetched all client roles', { returnedData: roles });
            return roles;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch client roles', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async deleteClientRole(roleName: string): Promise<void> {
        try {
            await CommonHelpers.retry(() => this.keycloakService.deleteClientRole(roleName));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('DELETE_CLIENT_ROLE', 'Client role deleted successfully', { roleName });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to delete client role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async addClientRoleToGroup(groupId: string, roleName: string): Promise<void> {
        try {
            await CommonHelpers.retry(() => this.keycloakService.addClientRoleToGroup(groupId, roleName));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('ADD_CLIENT_ROLE_TO_GROUP', 'Client role added to group', { groupId, roleName });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to add client role to group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async removeClientRoleFromGroup(groupId: string, roleName: string): Promise<void> {
        try {
            await CommonHelpers.retry(() => this.keycloakService.removeClientRoleFromGroup(groupId, roleName));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('REMOVE_CLIENT_ROLE_FROM_GROUP', 'Client role removed from group', { groupId, roleName });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to remove client role from group', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async addClientRoleToUser(userId: string, roleName: string): Promise<void> {
        const dbUser = await CommonHelpers.retry(() => this.databaseService.findUserById(userId));
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        try {
            await CommonHelpers.retry(() => this.keycloakService.addClientRoleToUser(dbUser.keycloakId, roleName));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('ADD_CLIENT_ROLE_TO_USER', 'Client role added to user', { userId, roleName });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to add client role to user', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async removeClientRoleFromUser(userId: string, roleName: string): Promise<void> {
        const dbUser = await CommonHelpers.retry(() => this.databaseService.findUserById(userId));
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        try {
            await CommonHelpers.retry(() => this.keycloakService.removeClientRoleFromUser(dbUser.keycloakId, roleName));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('REMOVE_CLIENT_ROLE_FROM_USER', 'Client role removed from user', { userId, roleName });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to remove client role from user', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async findUsersByClientRole(roleName: string): Promise<any[]> {
        try {
            const users = await CommonHelpers.retry(() => this.keycloakService.findUsersByClientRole(roleName));
            this.loggerService.logAction('FIND_USERS_BY_CLIENT_ROLE', 'Fetched users by client role', { roleName, returnedData: users });
            return users;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch users by client role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async findClientRolesByUserId(userId: string): Promise<any[]> {
        const dbUser = await CommonHelpers.retry(() => this.databaseService.findUserById(userId));
        if (!dbUser || !dbUser.keycloakId) {
            throw new HttpException('User not found or Keycloak ID missing', HttpStatus.NOT_FOUND);
        }
        try {
            const roles = await CommonHelpers.retry(() => this.keycloakService.findClientRolesByUserId(dbUser.keycloakId));
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
            const createdClient = await CommonHelpers.retry(() => this.keycloakService.createClient(clientData));
            this.loggerService.logAction('CREATE_CLIENT', 'Client created successfully', { clientData });
            return createdClient;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to create client', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async deleteClient(clientId: string): Promise<void> {
        try {
            await CommonHelpers.retry(() => this.keycloakService.deleteClient(clientId));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('DELETE_CLIENT', 'Client deleted successfully', { clientId });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to delete client', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async updateClient(clientId: string, clientData: any): Promise<any> {
        try {
            const updatedClient = await CommonHelpers.retry(() => this.keycloakService.updateClient(clientId, clientData));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('UPDATE_CLIENT', 'Client updated successfully', { clientId, clientData });
            return updatedClient;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to update client', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getClientByName(clientName: string): Promise<any> {
        try {
            const client = await CommonHelpers.retry(() => this.keycloakService.getClientByName(clientName));
            this.loggerService.logAction('GET_CLIENT_BY_NAME', 'Fetched client by name', { clientName, returnedData: client });
            return client;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch client by name', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getClientById(clientId: string): Promise<any> {
        try {
            const client = await CommonHelpers.retry(() => this.keycloakService.getClientById(clientId));
            this.loggerService.logAction('GET_CLIENT_BY_ID', 'Fetched client by ID', { clientId, returnedData: client });
            return client;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch client by ID', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async getAllClients(): Promise<any[]> {
        try {
            const clients = await CommonHelpers.retry(() => this.keycloakService.getAllClients());
            this.loggerService.logAction('GET_ALL_CLIENTS', 'Fetched all clients', { returnedData: clients });
            return clients;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to fetch all clients', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async addClientRole(clientId: string, roleName: string, description: string): Promise<void> {
        try {
            await CommonHelpers.retry(() => this.keycloakService.addClientRole(clientId, roleName, description));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('ADD_CLIENT_ROLE', 'Client role added successfully', { clientId, roleName, description });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to add client role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async removeClientRole(clientId: string, roleName: string): Promise<void> {
        try {
            await CommonHelpers.retry(() => this.keycloakService.removeClientRole(clientId, roleName));
            await this.invalidateUserCacheByPattern();
            this.loggerService.logAction('REMOVE_CLIENT_ROLE', 'Client role removed successfully', { clientId, roleName });
        } catch (error) {
            throw new HttpException(error.message || 'Failed to remove client role', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    async regenerateClientSecret(clientId: string): Promise<any> {
        try {
            const newSecret = await CommonHelpers.retry(() => this.keycloakService.regenerateClientSecret(clientId));
            this.loggerService.logAction('REGENERATE_CLIENT_SECRET', 'Client secret regenerated successfully', { clientId, newSecret });
            return newSecret;
        } catch (error) {
            throw new HttpException(error.message || 'Failed to regenerate client secret', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}