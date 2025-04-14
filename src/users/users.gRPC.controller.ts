// src/users/users.grpc.controller.ts
import { Controller } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Controller()
export class UsersGrpcController {
    constructor(private readonly usersService: UsersService) { }


    @GrpcMethod('UserService', 'Create')
    async create(data: CreateUserDto) {
        return this.usersService.createUser(data);
    }

    @GrpcMethod('UserService', 'Update')
    async update(data: { id: string; updateData: UpdateUserDto }) {
        const { id, ...updateData } = data;
        return this.usersService.updateUser(id, updateData);
    }

    @GrpcMethod('UserService', 'AssignRole')
    async assignRole(data: { id: string; role: string }) {
        const { id, role } = data;
        return this.usersService.assignRole(id, role);
    }

    @GrpcMethod('UserService', 'DeAssignRole')
    async deAssignRole(data: { id: string; role: string }) {
        const { id, role } = data;
        return this.usersService.deAssignRole(id, role);
    }

    @GrpcMethod('UserService', 'DeleteUser')
    async deleteUser(data: { id: string }) {
        return this.usersService.deleteUser(data.id);
    }

    @GrpcMethod('UserService', 'FindAllByRole')
    async findByRole(role: string) {
        return this.usersService.findAllUsersByRole(role);
    }

    @GrpcMethod('UserService', 'FindAll')
    async findAll() {
        return this.usersService.findAllUsers();
    }

    @GrpcMethod('UserService', 'FindById')
    findById(id: string) {
        return this.usersService.findUserById(id);
    }

    @GrpcMethod('UserService', 'FindByUsername')
    findByName(username: string) {
        return this.usersService.findUserByUsername(username);
    }

    @GrpcMethod('UserService', 'FindByEmail')
    findByEmail(email: string) {
        return this.usersService.findUserByEmail(email);
    }
}