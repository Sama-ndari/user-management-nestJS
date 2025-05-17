//src/database/database.service.ts
import { Injectable, NotFoundException } from '@nestjs/common';
import { User, UserDocument } from 'src/users/entities/user.entity';
import { InjectModel } from '@nestjs/mongoose';
import { ClientSession, Model } from 'mongoose';
import { CommonHelpers } from 'src/common/helpers';
import { PageOptionsDto } from 'src/common/page-options-dto/page-options-dto';
import { PageMetaDto } from 'src/common/page-meta-dto/page-meta-dto';
import { PageDto } from 'src/common/page-dto/page-dto';
import { SearchUserDto } from 'src/users/dto/create-user.dto';

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
                keycloakId: userDto.keycloakId,
                firstName: userDto.firstName,
                lastName: userDto.lastName,
                phone: userDto.phone,
                address: userDto.address,
                cardNumber: userDto.cardNumber,
                logo: userDto.logo,
                status: userDto.status || 'pending',

            }).filter(([_, value]) => value !== undefined && value !== null)
        );
        console.log('newUser', newUser);

        return CommonHelpers.retry(async () => {
            const createdUser = await this.UserModel.create([newUser], { session });
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
                    keycloakId: userDto.keycloakId,
                    firstName: userDto.firstName,
                    lastName: userDto.lastName,
                    phone: userDto.phone,
                    address: userDto.address,
                    cardNumber: userDto.cardNumber,
                    logo: userDto.logo,
                    status: userDto.status || 'pending',
                }).filter(([_, value]) => value !== undefined && value !== null)
            );

            const updatedUser = await this.UserModel.findByIdAndUpdate(id, user, { new: true, session }).lean();
            if (!updatedUser) throw new NotFoundException('User not found');
            return updatedUser;
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
            return user;
        } catch (error) {
            throw new Error(`Error finding user by ID: ${error.message}`);
        }
    }

    async findUserByKeycloakId(keycloakId: string): Promise<any> {
        try {
            const user = await CommonHelpers.retry(async () => {
                const user = await this.UserModel.findOne({ keycloakId }).lean();
                if (!user) {
                    throw new NotFoundException('User not found');
                }
                return user;
            });
            return user;
        } catch (error) {
            throw new Error(`Error finding user by Keycloak ID: ${error.message}`);
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
    
    async findAllUsers(
        pageOptionsDto: PageOptionsDto,
        searchUserDto?: SearchUserDto
    ): Promise<PageDto<any>> {
        try {
            const query = {};

            // Add search functionality
            if (searchUserDto?.search && searchUserDto.search.trim() !== '') {
                const searchRegex = new RegExp(searchUserDto.search, 'i');
                query['$or'] = [
                    { username: searchRegex },
                    { email: searchRegex },
                    { firstName: searchRegex },
                    { lastName: searchRegex }
                ];
            }

            const take = pageOptionsDto.take ?? 10; 
            const skip = pageOptionsDto.skip ?? 0;

            const users = await CommonHelpers.retry(async () => {
                return await this.UserModel.find(query)
                .limit(take)
                .skip(skip)
                .lean()
                .exec();
            });
            const items = users.map(user => CommonHelpers.transformDocument(user));
            const itemCount = await this.UserModel.countDocuments(query).exec();
            const pageMetaDto = new PageMetaDto({ itemCount, pageOptionsDto });

            return new PageDto(items, pageMetaDto);
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

    async findAllUsersByStatus(status: string, pageOptionsDto?: PageOptionsDto): Promise<PageDto<any>> {
        try {

            if (!pageOptionsDto) {
                pageOptionsDto = new PageOptionsDto();
            }
            const take = pageOptionsDto.take ?? 10; 
            const skip = pageOptionsDto.skip ?? 0;
            const users = await CommonHelpers.retry(async () => {
                const users = await this.UserModel.find({ status })
                    .limit(take)
                    .skip(skip)
                    .lean()
                    .exec();
                return users;
            });
            const items = users.map(user => CommonHelpers.transformDocument(user));
            const itemCount = await this.UserModel.countDocuments({ status }).exec();
            const pageMetaDto = new PageMetaDto({ itemCount, pageOptionsDto });
            return new PageDto(items, pageMetaDto);
        } catch (error) {
            throw new Error(`Error finding users by status: ${error.message}`);
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

