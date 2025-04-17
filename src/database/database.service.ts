import { Injectable, NotFoundException } from '@nestjs/common';
import { KeycloakService } from '../keycloak/keycloak.service';
import { CreateUserDatabaseDto, CreateUserDto, UserRepresentation } from '../users/dto/create-user.dto';
import { User, UserDocument } from 'src/users/entities/user.entity';
import { InjectModel } from '@nestjs/mongoose';
import { ClientSession, Model } from 'mongoose';
import { CommonHelpers } from 'src/common/helpers';

@Injectable()
export class DatabaseService {
    constructor(
        @InjectModel(User.name) private readonly UserModel: Model<UserDocument>,
    ) { }

    async createUser(userDto: any, session?: ClientSession): Promise<any> {
        // Check if username or email already exists
        const existingUser = await this.UserModel.findOne({
            $or: [{ username: userDto.username }, { email: userDto.email }]
        }).exec();

        if (existingUser) {
            throw new Error('Username or email already exists');
        }

        const newUser = Object.fromEntries(
            Object.entries({
                username: userDto.username,
                email: userDto.email,
                // password: userDto.password,
                keycloakId: userDto.keycloakId,
                firstName: userDto.firstName,
                lastName: userDto.lastName,
                phone: userDto.phone,
                address: userDto.address,
                cardNumber: userDto.cardNumber,
                logo: userDto.logo,
                status: userDto.status || 'pending',
                // role: userDto.role,
            }).filter(([_, value]) => value !== undefined && value !== null)
        );

        return CommonHelpers.retry(async () => {
            const createdUser = await this.UserModel.create([newUser], { session });
            // await this.invalidatePartnersCache();
            // console.log('Cache invalidated after create');
            return createdUser;
        });
    }

    async updateUser(id: string, userDto: any, session?: ClientSession): Promise<any> {
        return CommonHelpers.retry(async () => {
            const existingUser = await this.UserModel.findById(id).exec();
            if (!existingUser) {
                throw new NotFoundException('User not found');
            }
        

            const user = Object.fromEntries(
                Object.entries({
                    username: userDto.username,
                    email: userDto.email,
                    // password: userDto.password,
                    keycloakId: userDto.keycloakId,
                    firstName: userDto.firstName,
                    lastName: userDto.lastName,
                    phone: userDto.phone,
                    address: userDto.address,
                    cardNumber: userDto.cardNumber,
                    logo: userDto.logo,
                    status: userDto.status || 'pending',
                    // role: userDto.role,
                }).filter(([_, value]) => value !== undefined && value !== null)
            );

            const updatedUser = await this.UserModel.findByIdAndUpdate(id, user, { new: true, session }).lean();
            if (!updatedUser) throw new NotFoundException('User not found');
            return updatedUser;
        });
    }

    async updateUserRole2(id: string, roleName: string, addRole: boolean, session?: ClientSession): Promise<any> {
        return CommonHelpers.retry(async () => {
            const user = await this.UserModel.findById(id).exec();
            if (!user) {
                throw new NotFoundException('User not found');
            }
            let updatedUser;

            if (addRole) {
                const newUser = { role: roleName };
                updatedUser = await this.UserModel.findByIdAndUpdate(id, newUser, { new: true, session }).lean();
            } else {
                updatedUser = await this.UserModel.findByIdAndUpdate(id, { role: null }, { new: true, session }).lean();
            }
            return CommonHelpers.transformDocument(updatedUser);
        });
    }


    async findUserById(id: string): Promise<any> {
        try {
            const user = await CommonHelpers.retry(async () => {
                const user = await this.UserModel.findById(id).lean();
                if (!user) {
                    throw new NotFoundException('User not found');
                }
                return user;
            });
            if (!user) {
                throw new NotFoundException('User not found');
            }
            return user;
        } catch (error) {
            throw new Error(`Error finding user by ID: ${error.message}`);
        }
    }

    async findUserByUsername(username: string): Promise<any> {
        try {
            const user = await CommonHelpers.retry(async () => {
                const user = await this.UserModel.findOne({ username }).exec();
                if (!user) {
                    throw new NotFoundException('User not found');
                }
                return user;
            });
            return user;
        } catch (error) {
            throw new Error(`Error finding user by username: ${error.message}`);
        }
    }

    async findAllUsersByRole2(roleName: string, pageOptionsDto?: any): Promise<any[]> {
        try {
            const foundUsers = await CommonHelpers.retry(async () => {
                const users = await this.UserModel.find({ 'role': roleName })
                    .lean()
                    .exec();
                if (!users || users.length === 0) {
                    throw new NotFoundException('No users found for the specified role');
                }
                return users.map(user => CommonHelpers.transformDocument(user));
            });

            // const users = await this.UserModel.find({ 'role': roleName })
            // .limit(pageOptionsDto.take)
            // .skip(pageOptionsDto.skip)
            // .lean()
            // .exec();

            // const items = users.map(user => CommonHelpers.transformDocument(user));
            // const itemCount = await this.UserModel.countDocuments({ [field]: value }).exec();
            // const pageMetaDto = new PageMetaDto({ itemCount, pageOptionsDto });
            // return new PageDto(items, pageMetaDto);
            return foundUsers;
        } catch (error) {
            throw new Error(`Error finding users by role: ${error.message}`);
        }
    }

    async findAllUsers(pageOptionsDto?: any): Promise<UserRepresentation[]> {
        try {
            const users = await CommonHelpers.retry(async () => {
                const users = await this.UserModel.find().lean().exec();
                if (!users || users.length === 0) {
                    throw new NotFoundException('No users found');
                }
                return users;
            });
            const foundUsers = users.map(user => CommonHelpers.transformDocument(user));
            // const users = await this.UserModel.find()
            // .limit(pageOptionsDto.take)
            // .skip(pageOptionsDto.skip)
            // .lean()
            // .exec();

            // const items = users.map(user => CommonHelpers.transformDocument(user));
            // const itemCount = await this.UserModel.countDocuments({ [field]: value }).exec();
            // const pageMetaDto = new PageMetaDto({ itemCount, pageOptionsDto });
            // return new PageDto(items, pageMetaDto);
            return foundUsers;
        } catch (error) {
            throw new Error(`Error finding all users: ${error.message}`);
        }
    }

    async findUserByEmail(email: string): Promise<any> {
        try {
            const user = await CommonHelpers.retry(async () => {
                const user = await this.UserModel.findOne({ email }).exec();
                if (!user) {
                    throw new NotFoundException('User not found');
                }
                return user;
            });
            return user;
        } catch (error) {
            throw new Error(`Error finding user by email: ${error.message}`);
        }
    }

    async deleteUser(id: string, session?: ClientSession) {
        try {
            const result = await CommonHelpers.retry(async () => {
                const user = await this.UserModel.findByIdAndDelete(id, { session }).lean().exec();
                if (!user) {
                    throw new NotFoundException('User not found');
                }
                return user;
            });
            return CommonHelpers.transformDocument(result);
        } catch (error) {
            throw new Error(`Error deleting user: ${error.message}`);
        }
    }
}