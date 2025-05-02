import { Controller, Post, Body, Get, Request, Patch, Delete, Param, Put, HttpCode, HttpStatus, Query, Res, UseGuards, Req } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto, ResetPasswordDto } from './dto/create-user.dto';
import { Roles } from 'nest-keycloak-connect';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiParam, ApiQuery, ApiTags } from '@nestjs/swagger';
import { UpdateUserDto } from './dto/update-user.dto';
import { LoginDto } from './dto/login.dto';
import { LogoutDto } from './dto/logout.dto';
import { PageOptionsDto } from 'src/common/page-options-dto/page-options-dto';
import { CreateGroupDto, UpdateGrouprDto } from './dto/create-group.dto';
import { Response } from 'express';
import { AuthGuard } from '@nestjs/passport';

@ApiTags('User Waangu Marketplace')
@Controller('users')
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
  ) { }




  // ==============================
  // Miscellaneous Endpoints
  // ==============================



  @Get('actions')
  @ApiOperation({ summary: 'Get all user actions' })
  @Roles({ roles: ['Admin'] }) // Only Admins can view actions
  async getAllActions(): Promise<string[]> {
    return this.usersService.getAllActions();
  }

  @Get('logs/audit')
  @ApiOperation({ summary: 'Get audit logs with optional filters' })
  @ApiQuery({ name: 'date', required: false, description: "Format: 'YYYY-MM-DD'" })
  @ApiQuery({ name: 'actor', required: false, description: "Username of the Actor or 'system'" })
  @ApiQuery({ name: 'action', required: false, description: "Name of the Action" })
  @ApiQuery({ name: 'startTime', required: false, description: "Format: 'HH:mm'" })
  @ApiQuery({ name: 'endTime', required: false, description: "Format: 'HH:mm'" })
  async getAuditLog(
    @Res() res: Response,
    @Query('date') date?: string,
    @Query('actor') actor?: string,
    @Query('action') action?: string,
    @Query('startTime') startTime?: string,
    @Query('endTime') endTime?: string,
  ) {
    const logs = await this.usersService.getAuditLogs({ date: date || null, actor: actor || null, action: action || null, startTime: startTime || null, endTime: endTime || null });
    if (logs === null) {
      res.status(404).send('Log file not found');
    } else {
      res.json(logs);
    }
  }


  // src/users/users.controller.ts
  // Note: Only the new endpoint is shown; add it to your existing UsersController

  @Delete('logs/audit')
  @ApiOperation({ summary: 'Delete audit logs with optional filters' })
  @ApiQuery({ name: 'date', required: false, description: "Format: 'YYYY-MM-DD'" })
  @ApiQuery({ name: 'actor', required: false, description: "Username of the Actor or 'system'" })
  @ApiQuery({ name: 'action', required: false, description: "Name of the Action" })
  @ApiQuery({ name: 'startTime', required: false, description: "Format: 'HH:mm'" })
  @ApiQuery({ name: 'endTime', required: false, description: "Format: 'HH:mm'" })
  // @UseGuards(AuthGuard('jwt'))
  async deleteAuditLog(
    @Res() res: Response,
    @Query('date') date?: string,
    @Query('actor') actor?: string,
    @Query('action') action?: string,
    @Query('startTime') startTime?: string,
    @Query('endTime') endTime?: string,
  ) {

    const result = await this.usersService.deleteAuditLogs({
      date: date || null,
      actor: actor || null,
      action: action || null,
      startTime: startTime || null,
      endTime: endTime || null,
    });
    return res.json({ message: 'Logs deleted successfully', deletedCount: result.deletedCount });
  }

  // ==============================
  // User Endpoints
  // ==============================



  @Post()
  @ApiOperation({ summary: 'Create a new user' })
  @UseGuards(AuthGuard('jwt'))
  @ApiBody({ type: CreateUserDto })
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.createUser(createUserDto);
  }

  @Post('without-roles')
  @ApiOperation({ summary: 'Create a new user without Group and Role' })
  @UseGuards(AuthGuard('jwt'))
  @ApiBody({ type: CreateUserDto })
  @Roles({ roles: ['Admin'] }) // Only Admins can create users
  createUserWithoutRoles(@Body() createUserDto: CreateUserDto) {
    return this.usersService.createUserWithoutRoles(createUserDto);
  }

  @Put('/:id')
  @ApiParam({ name: 'id', description: 'User ID' })
  @ApiBody({ type: UpdateUserDto })
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({ summary: 'Update a user' })
  update(@Param('id') id: string, @Body() updateData: UpdateUserDto) {
    return this.usersService.updateUser(id, updateData);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete a user' })
  @UseGuards(AuthGuard('jwt'))
  async delete(@Param('id') id: string) {
    return this.usersService.deleteUser(id);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login a user' })
  @ApiBody({ type: LoginDto })
  async login(@Body() body: { identifier: string; password: string }): Promise<any> {
    const tokenData = await this.usersService.login(body);
    return { message: 'Login successful', tokenData };
  }

  @Post('logout')
  @ApiOperation({ summary: 'Logout a user' })
  @UseGuards(AuthGuard('jwt'))
  @ApiBody({ type: LogoutDto })
  async logout(@Body() body: { refreshToken: string }): Promise<any> {
    await this.usersService.logout(body.refreshToken);
    return { message: 'Logout successful' };
  }

  @Post('reset-password/:id')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({ summary: 'Reset a user password' })
  @ApiBody({ type: ResetPasswordDto })
  async resetPassword(
    @Param('id') id: string,
    @Body() body: ResetPasswordDto,
  ): Promise<any> {
    const updatedUser = await this.usersService.resetPassword(id, body.newPassword);
    return { message: 'Password reset successfully', user: updatedUser };
  }

  @Post('refresh-token')
  @HttpCode(HttpStatus.OK)
  // @UseGuards(AuthGuard('jwt'))
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiBody({
    schema: {
      properties: {
        refresh: { type: 'string', example: 'refresh_token' }
      }
    }
  })
  async refreshAccessToken(@Body() body: { refresh: string }): Promise<any> {
    const newAccessToken = await this.usersService.refreshAccessToken(body.refresh);
    return { access: newAccessToken };
  }

  @Post('decode-token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Decode an access token' })
  @ApiBody({
    schema: {
      properties: {
        accessToken: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' }
      }
    }
  })
  async decodeToken(@Body() body: { accessToken: string }): Promise<any> {
    const decodedData = await this.usersService.decodeToken(body.accessToken);
    return { message: 'Token decoded successfully', decodedData };
  }

  @Get()
  @ApiOperation({ summary: 'Find all users' })
  // @UseGuards(AuthGuard('jwt'))
  async findAll(@Query() pageOptionsDto: PageOptionsDto) {
    return await this.usersService.findAllUsers(pageOptionsDto);
  }

  @Get('connected')
  @ApiOperation({ summary: 'Find all connected users' })
  // @UseGuards(AuthGuard('jwt'))
  findAllConnected() {
    return this.usersService.getConnectedUsers();
  }

  @Get('by-id/:id')
  @ApiOperation({ summary: 'Find a user by ID' })
  // @UseGuards(AuthGuard('jwt'))
  findById(@Param('id') id: string) {
    return this.usersService.findUserById(id);
  }

  @Get('by-username/:username')
  @ApiOperation({ summary: 'Find a user by username' })
  // @UseGuards(AuthGuard('jwt'))
  findByName(@Param('username') username: string) {
    return this.usersService.findUserByUsername(username);
  }

  @Get('by-email/:email')
  @ApiOperation({ summary: 'Find a user by email' })
  // @UseGuards(AuthGuard('jwt'))
  findByEmail(@Param('email') email: string) {
    return this.usersService.findUserByEmail(email);
  }



  // ==============================
  // Realm Role Endpoints
  // ==============================



  @Post('role')
  @ApiOperation({ summary: 'Create a new Realm role' })
  @ApiBody({
    schema: {
      properties: {
        roleName: { type: 'string', example: 'Admin' },
        description: { type: 'string', example: 'Administrator role with full access' }
      }
    }
  })
  @UseGuards(AuthGuard('jwt'))
  async createRealmRole(@Body() body: { roleName: string; description: string }): Promise<any> {
    await this.usersService.createRealmRole(body.roleName, body.description);
    return { message: `Role '${body.roleName}' created successfully.` };
  }

  @Put('roles/:roleName')
  @ApiParam({ name: 'roleName', description: 'RealmRole name to update' })
  @ApiBody({
    schema: {
      properties: {
        newName: { type: 'string', example: 'UpdatedRoleName' },
        newDescription: { type: 'string', example: 'Updated description for the role' }
      }
    }
  })
  @ApiOperation({ summary: 'Update a Realm role name or description' })
  @UseGuards(AuthGuard('jwt'))
  async updateRealmRole(
    @Param('roleName') roleName: string,
    @Body() body: { newName?: string; newDescription?: string }
  ): Promise<any> {
    await this.usersService.updateRealmRole(roleName, body.newName, body.newDescription);
    return { message: `Role '${roleName}' updated successfully.` };
  }

  @Delete('roles/:roleName')
  @ApiParam({ name: 'roleName', description: 'RealmRole name to delete' })
  @ApiOperation({ summary: 'Delete a realm role' })
  @UseGuards(AuthGuard('jwt'))
  async deleteRealmRole(@Param('roleName') roleName: string): Promise<any> {
    await this.usersService.deleteRealmRole(roleName);
    return { message: `Role '${roleName}' deleted successfully.` };
  }

  @Get('roles')
  @ApiOperation({ summary: 'Get all Realm roles' })
  @UseGuards(AuthGuard('jwt'))
  async getAllRealmRoles(): Promise<any[]> {
    return this.usersService.getAllRealmRoles();
  }

  @Get('users-by-role/:role')
  @ApiOperation({ summary: 'Find all users by Realm role name' })
  @UseGuards(AuthGuard('jwt'))
  findByRealmRole(@Param('role') role: string) {
    return this.usersService.findAllUsersByRealmRole(role);
  }

  @Get(':userId/roles')
  @ApiParam({ name: 'userId', description: 'User ID' })
  @ApiOperation({ summary: 'Get all Realm roles of a user' })
  @UseGuards(AuthGuard('jwt'))
  async getUserRealmRoles(@Param('userId') userId: string): Promise<any[]> {
    return this.usersService.getUserRealmRoles(userId);
  }

  // @Put('/:id/assign-role/:role')
  // @ApiParam({ name: 'id', description: 'User ID' })
  // @ApiParam({ name: 'role', description: 'Role name' })
  // @ApiOperation({ summary: 'Assign a Realm role' })
  // @UseGuards(AuthGuard('jwt'))
  // async assignRole(@Param('id') userId: string, @Param('role') role: string) {
  //   await this.usersService.assignRole(userId, role);
  // }

  // @Put('/:id/deassign-role/:role')
  // @ApiParam({ name: 'id', description: 'User ID' })
  // @ApiParam({ name: 'role', description: 'Role name' })
  // @ApiOperation({ summary: 'Deassign a Realm role' })
  // @UseGuards(AuthGuard('jwt'))
  // async deAssignRealmRole(@Param('id') userId: string, @Param('role') role: string) {
  //   await this.usersService.deAssignRealmRole(userId, role);
  // }



  // ==============================
  // Group Endpoints
  // ======
  // ========================



  @Post('groups')
  @ApiOperation({ summary: 'Create a new group' })
  @ApiBody({ type: CreateGroupDto })
  @UseGuards(AuthGuard('jwt'))
  async createGroup(@Body() createGroupDto: CreateGroupDto): Promise<any> {
    await this.usersService.createGroup(createGroupDto.name, createGroupDto.attributes);
    return { message: `Group '${createGroupDto.name}' created successfully.` };
  }

  @Put('groups/:groupId')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiOperation({ summary: 'Update a group' })
  @ApiBody({ type: UpdateGrouprDto })
  @UseGuards(AuthGuard('jwt'))
  async updateGroup(
    @Param('groupId') groupId: string,
    @Body() updateGroupDto: UpdateGrouprDto,
  ): Promise<any> {
    await this.usersService.updateGroup(groupId, updateGroupDto.name, updateGroupDto.attributes);
    return { message: `Group '${groupId}' updated successfully.` };
  }

  @Delete('groups/:groupId')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiOperation({ summary: 'Delete a group' })
  @UseGuards(AuthGuard('jwt'))
  async deleteGroup(@Param('groupId') groupId: string): Promise<any> {
    await this.usersService.deleteGroup(groupId);
    return { message: `Group '${groupId}' deleted successfully.` };
  }

  @Get('groups')
  @ApiOperation({ summary: 'Get all groups' })
  @UseGuards(AuthGuard('jwt'))
  async getAllGroups(): Promise<any[]> {
    return this.usersService.getAllGroups();
  }

  @Get('groups/:groupId')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiOperation({ summary: 'Get group details by ID' })
  @UseGuards(AuthGuard('jwt'))
  async getGroupById(@Param('groupId') groupId: string): Promise<any> {
    return this.usersService.getGroupById(groupId);
  }

  @Get('groups/by-name/:groupName')
  @ApiParam({ name: 'groupName', description: 'Group name' })
  @ApiOperation({ summary: 'Get group details by name' })
  @UseGuards(AuthGuard('jwt'))
  async getGroupByName(@Param('groupName') groupName: string): Promise<any> {
    return this.usersService.getGroupByName(groupName);
  }

  @Get(':userId/groups')
  @ApiParam({ name: 'userId', description: 'User ID' })
  @ApiOperation({ summary: 'Get all groups for a user' })
  @UseGuards(AuthGuard('jwt'))
  async getUserGroups(@Param('userId') userId: string): Promise<any[]> {
    return this.usersService.getUserGroups(userId);
  }

  @Put('groups/:groupId/users/:userId')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiParam({ name: 'userId', description: 'User Database ID' })
  @ApiOperation({ summary: 'Add a user to a group' })
  @UseGuards(AuthGuard('jwt'))
  async addUserToGroup(@Param('userId') userId: string, @Param('groupId') groupId: string): Promise<any> {
    await this.usersService.addUserToGroup(userId, groupId);
    return { message: `User '${userId}' added to group '${groupId}' successfully.` };
  }

  @Delete('groups/:groupId/users/:userId')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiParam({ name: 'userId', description: 'User Database ID' })
  @ApiOperation({ summary: 'Remove a user from a group' })
  @UseGuards(AuthGuard('jwt'))
  async removeUserFromGroup(@Param('userId') userId: string, @Param('groupId') groupId: string): Promise<any> {
    await this.usersService.removeUserFromGroup(userId, groupId);
    return { message: `User '${userId}' removed from group '${groupId}' successfully.` };
  }

  @Get('groups/:groupId/users')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiOperation({ summary: 'Get all users in a group' })
  @UseGuards(AuthGuard('jwt'))
  async getAllUsersFromGroup(@Param('groupId') groupId: string): Promise<any[]> {
    return this.usersService.getAllUsersFromGroup(groupId);
  }

  @Post('groups/:groupId/roles/:roleName')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiParam({ name: 'roleName', description: 'Role name' })
  @ApiOperation({ summary: 'Add a role to a group' })
  @UseGuards(AuthGuard('jwt'))
  async addRoleToGroup(@Param('groupId') groupId: string, @Param('roleName') roleName: string): Promise<any> {
    await this.usersService.addRoleToGroup(groupId, roleName);
    return { message: `Role '${roleName}' added to group '${groupId}' successfully.` };
  }

  @Delete('groups/:groupId/roles/:roleName')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiParam({ name: 'roleName', description: 'Role name' })
  @ApiOperation({ summary: 'Remove a role from a group' })
  @UseGuards(AuthGuard('jwt'))
  async removeRoleFromGroup(@Param('groupId') groupId: string, @Param('roleName') roleName: string): Promise<any> {
    await this.usersService.removeRoleFromGroup(groupId, roleName);
    return { message: `Role '${roleName}' removed from group '${groupId}' successfully.` };
  }

  @Get('groups/:groupId/roles')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiOperation({ summary: 'Get roles assigned to a group' })
  @UseGuards(AuthGuard('jwt'))
  async getGroupRoles(@Param('groupId') groupId: string): Promise<any> {
    return this.usersService.getGroupRoles(groupId);
  }




  // ==============================
  // Cient Role Endpoints
  // ==============================


  @Post('client-roles')
  @ApiOperation({ summary: 'Create a new Client role' })
  @ApiBody({
    schema: {
      properties: {
        roleName: { type: 'string', example: 'ClientAdmin' },
        description: { type: 'string', example: 'Client-specific admin role' }
      }
    }
  })
  @UseGuards(AuthGuard('jwt'))
  async createClientRole(@Body() body: { roleName: string; description: string }): Promise<any> {
    await this.usersService.createClientRole(body.roleName, body.description);
    return { message: `Client role '${body.roleName}' created successfully.` };
  }

  @Put('client-roles/:roleName')
  @ApiParam({ name: 'roleName', description: 'Client role name to update' })
  @ApiBody({
    schema: {
      properties: {
        newName: { type: 'string', example: 'UpdatedClientRoleName' },
        newDescription: { type: 'string', example: 'Updated description for the client role' }
      }
    }
  })
  @ApiOperation({ summary: 'Update a Client role name or description' })
  @UseGuards(AuthGuard('jwt'))
  async updateClientRole(
    @Param('roleName') roleName: string,
    @Body() body: { newName?: string; newDescription?: string }
  ): Promise<any> {
    await this.usersService.updateClientRole(roleName, body.newName, body.newDescription);
    return { message: `Client role '${roleName}' updated successfully.` };
  }

  @Get('client-roles')
  @ApiOperation({ summary: 'Get all Client roles' })
  @UseGuards(AuthGuard('jwt'))
  async getAllClientRoles(): Promise<any[]> {
    return this.usersService.getAllClientRoles();
  }

  @Delete('client-roles/:roleName')
  @ApiParam({ name: 'roleName', description: 'Client role name to delete' })
  @ApiOperation({ summary: 'Delete a Client role' })
  @UseGuards(AuthGuard('jwt'))
  async deleteClientRole(@Param('roleName') roleName: string): Promise<any> {
    await this.usersService.deleteClientRole(roleName);
    return { message: `Client role '${roleName}' deleted successfully.` };
  }

  @Post('client-roles/:roleName/groups/:groupId')
  @ApiParam({ name: 'roleName', description: 'Client role name' })
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiOperation({ summary: 'Add a Client role to a group' })
  @UseGuards(AuthGuard('jwt'))
  async addClientRoleToGroup(
    @Param('groupId') groupId: string,
    @Param('roleName') roleName: string
  ): Promise<any> {
    await this.usersService.addClientRoleToGroup(groupId, roleName);
    return { message: `Client role '${roleName}' added to group '${groupId}' successfully.` };
  }

  @Delete('client-roles/:roleName/groups/:groupId')
  @ApiParam({ name: 'roleName', description: 'Client role name' })
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiOperation({ summary: 'Remove a Client role from a group' })
  @UseGuards(AuthGuard('jwt'))
  async removeClientRoleFromGroup(
    @Param('groupId') groupId: string,
    @Param('roleName') roleName: string
  ): Promise<any> {
    await this.usersService.removeClientRoleFromGroup(groupId, roleName);
    return { message: `Client role '${roleName}' removed from group '${groupId}' successfully.` };
  }

  @Post('client-roles/:roleName/users/:userId')
  @ApiParam({ name: 'roleName', description: 'Client role name' })
  @ApiParam({ name: 'userId', description: 'User ID' })
  @ApiOperation({ summary: 'Add a Client role to a user' })
  @UseGuards(AuthGuard('jwt'))
  async addClientRoleToUser(
    @Param('userId') userId: string,
    @Param('roleName') roleName: string
  ): Promise<any> {
    await this.usersService.addClientRoleToUser(userId, roleName);
    return { message: `Client role '${roleName}' added to user '${userId}' successfully.` };
  }

  @Delete('client-roles/:roleName/users/:userId')
  @ApiParam({ name: 'roleName', description: 'Client role name' })
  @ApiParam({ name: 'userId', description: 'User ID' })
  @ApiOperation({ summary: 'Remove a Client role from a user' })
  @UseGuards(AuthGuard('jwt'))
  async removeClientRoleFromUser(
    @Param('userId') userId: string,
    @Param('roleName') roleName: string
  ): Promise<any> {
    await this.usersService.removeClientRoleFromUser(userId, roleName);
    return { message: `Client role '${roleName}' removed from user '${userId}' successfully.` };
  }

  @Get('client-roles/users/:userId')
  @ApiParam({ name: 'userId', description: 'User ID' })
  @ApiOperation({ summary: 'Find all Client roles by User ID' })
  @UseGuards(AuthGuard('jwt'))
  async findClientRolesByUserId(@Param('userId') userId: string): Promise<any[]> {
    return this.usersService.findClientRolesByUserId(userId);
  }

  @Get('client-roles/:roleName/users')
  @ApiParam({ name: 'roleName', description: 'Client role name' })
  @ApiOperation({ summary: 'Find all users by Client role name' })
  @UseGuards(AuthGuard('jwt'))
  async findUsersByClientRole(@Param('roleName') roleName: string): Promise<any[]> {
    return this.usersService.findUsersByClientRole(roleName);
  }



  // ==============================
  // Client Management Endpoints
  // ==============================



  @Post('clients')
  @ApiOperation({ summary: 'Create a new client' })
  @ApiBody({
    schema: {
      properties: {
        clientId: { type: 'string', example: 'my-client' },
        name: { type: 'string', example: 'My Client' },
        description: { type: 'string', example: 'Description of the client' },
      },
    },
  })
  @UseGuards(AuthGuard('jwt'))
  async createClient(@Body() clientData: any): Promise<any> {
    return this.usersService.createClient(clientData);
  }

  @Delete('clients/:clientId')
  @ApiParam({ name: 'clientId', description: 'Client ID' })
  @ApiOperation({ summary: 'Delete a client' })
  @UseGuards(AuthGuard('jwt'))
  async deleteClient(@Param('clientId') clientId: string): Promise<void> {
    return this.usersService.deleteClient(clientId);
  }

  @Put('clients/:clientId')
  @ApiParam({ name: 'clientId', description: 'Client ID' })
  @ApiBody({
    schema: {
      properties: {
        name: { type: 'string', example: 'Updated Client Name' },
        description: { type: 'string', example: 'Updated description' },
      },
    },
  })
  @ApiOperation({ summary: 'Update a client' })
  @UseGuards(AuthGuard('jwt'))
  async updateClient(
    @Param('clientId') clientId: string,
    @Body() clientData: any,
  ): Promise<any> {
    return this.usersService.updateClient(clientId, clientData);
  }

  @Get('clients/by-name/:clientName')
  @ApiParam({ name: 'clientName', description: 'Client Name' })
  @ApiOperation({ summary: 'Get a client by name: ClientID' })
  @UseGuards(AuthGuard('jwt'))
  async getClientByName(@Param('clientName') clientName: string): Promise<any> {
    return this.usersService.getClientByName(clientName);
  }

  @Get('clients/:clientId')
  @ApiParam({ name: 'clientId', description: 'Client ID' })
  @ApiOperation({ summary: 'Get a client by ID: ahahaj984-df98-df98-df98-df98-df98' })
  @UseGuards(AuthGuard('jwt'))
  async getClientById(@Param('clientId') clientId: string): Promise<any> {
    return this.usersService.getClientById(clientId);
  }

  @Get('clients')
  @ApiOperation({ summary: 'Get all clients' })
  @UseGuards(AuthGuard('jwt'))
  async getAllClients(): Promise<any[]> {
    return this.usersService.getAllClients();
  }

  @Post('clients/:clientId/roles')
  @ApiParam({ name: 'clientId', description: 'Client ID' })
  @ApiBody({
    schema: {
      properties: {
        roleName: { type: 'string', example: 'ClientRole' },
        description: { type: 'string', example: 'Description of the role' },
      },
    },
  })
  @ApiOperation({ summary: 'Add a role to a client' })
  @UseGuards(AuthGuard('jwt'))
  async addClientRole(
    @Param('clientId') clientId: string,
    @Body() body: { roleName: string; description: string },
  ): Promise<void> {
    return this.usersService.addClientRole(clientId, body.roleName, body.description);
  }

  @Delete('clients/:clientId/roles/:roleName')
  @ApiParam({ name: 'clientId', description: 'Client ID' })
  @ApiParam({ name: 'roleName', description: 'Role Name' })
  @ApiOperation({ summary: 'Remove a role from a client' })
  @UseGuards(AuthGuard('jwt'))
  async removeClientRole(
    @Param('clientId') clientId: string,
    @Param('roleName') roleName: string,
  ): Promise<void> {
    return this.usersService.removeClientRole(clientId, roleName);
  }

  @Post('clients/:clientId/regenerate-secret')
  @ApiParam({ name: 'clientId', description: 'Client ID' })
  @ApiOperation({ summary: 'Regenerate client secret' })
  @UseGuards(AuthGuard('jwt'))
  async regenerateClientSecret(@Param('clientId') clientId: string): Promise<any> {
    return this.usersService.regenerateClientSecret(clientId);
  }

}