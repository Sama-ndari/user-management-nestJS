import { Controller, Post, Body, Get, Request, Patch, Delete, Param, Put, HttpCode, HttpStatus, Query, Res, UseGuards, Req } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto, GoogleAuthDto, ResetPasswordDto, SearchUserDto } from './dto/create-user.dto';
import { Roles } from 'nest-keycloak-connect';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiParam, ApiQuery, ApiTags } from '@nestjs/swagger';
import { UpdateUserDto } from './dto/update-user.dto';
import { LoginDto } from './dto/login.dto';
import { LogoutDto } from './dto/logout.dto';
import { PageOptionsDto } from 'src/common/page-options-dto/page-options-dto';
import { CreateGroupDto, UpdateGrouprDto } from './dto/create-group.dto';
import { Response } from 'express';
import { AuthGuard } from '@nestjs/passport';
import { UserStatus } from './entities/user.entity';


@Controller('users')
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
  ) { }



  // ==============================
  // Miscellaneous Endpoints
  // ==============================



  
  @ApiTags('Audit & System')
  @Get('actions')
  @ApiOperation({ summary: 'Get all user actions' })
  // @ApiBearerAuth('JWT')
  // @UseGuards(AuthGuard('jwt'))
  @Roles({ roles: ['Admin'] })
  async getAllActions(@Request() req): Promise<string[]> {
    console.log('User:', req.user);
    return this.usersService.getAllActions();
  }

  @ApiTags('Audit & System')
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

  // @ApiTags('Audit & System')
  // @Delete('logs/audit')
  // @ApiOperation({ summary: 'Delete audit logs with optional filters' })
  // @ApiQuery({ name: 'date', required: false, description: "Format: 'YYYY-MM-DD'" })
  // @ApiQuery({ name: 'actor', required: false, description: "Username of the Actor or 'system'" })
  // @ApiQuery({ name: 'action', required: false, description: "Name of the Action" })
  // @ApiQuery({ name: 'startTime', required: false, description: "Format: 'HH:mm'" })
  // @ApiQuery({ name: 'endTime', required: false, description: "Format: 'HH:mm'" })
  // @ApiBearerAuth('JWT')
  // @UseGuards(AuthGuard('jwt'))
  // async deleteAuditLog(
  //   @Res() res: Response,
  //   @Query('date') date?: string,
  //   @Query('actor') actor?: string,
  //   @Query('action') action?: string,
  //   @Query('startTime') startTime?: string,
  //   @Query('endTime') endTime?: string,
  // ) {

  //   const result = await this.usersService.deleteAuditLogs({
  //     date: date || null,
  //     actor: actor || null,
  //     action: action || null,
  //     startTime: startTime || null,
  //     endTime: endTime || null,
  //   });
  //   return res.json({ message: 'Logs deleted successfully', deletedCount: result.deletedCount });
  // }

  // ==============================
  // User Endpoints
  // ==============================

  @ApiTags('User Management')
  @Post()
  @ApiOperation({ summary: 'Create a new user' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  @ApiBody({ type: CreateUserDto })
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.createUser(createUserDto);
  }

  @ApiTags('User Management')
  @Post('google-auth')
  @ApiOperation({ summary: 'Create or authenticate a user with Google' })
  //   @ApiBearerAuth('JWT')
  // @UseGuards(AuthGuard('jwt'))
  @ApiBody({ type: GoogleAuthDto })
  async googleAuth(@Body() googleAuthDto: GoogleAuthDto) {
    // return this.usersService.createUserWithGoogle(googleAuthDto);
  }

  @ApiTags('User Management')
  @Post('without-roles')
  @ApiOperation({ summary: 'Create a new user without Group and Role' })
  // @ApiBearerAuth('JWT')
  // @UseGuards(AuthGuard('jwt'))
  @ApiBody({ type: CreateUserDto })
  createUserWithoutRoles(@Body() createUserDto: CreateUserDto) {
    return this.usersService.createUserWithoutRoles(createUserDto);
  }

  @ApiTags('User Management')
  @Put('/:id')
  @ApiParam({ name: 'id', description: 'User ID' })
  @ApiBody({ type: UpdateUserDto })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  @ApiOperation({ summary: 'Update a user' })
  update(@Param('id') id: string, @Body() updateData: UpdateUserDto) {
    return this.usersService.updateUser(id, updateData);
  }

  @ApiTags('User Management')
  @Delete(':id')
  @ApiOperation({ summary: 'Delete a user' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async delete(@Param('id') id: string) {
    return this.usersService.deleteUser(id);
  }

  @ApiTags('Authentication')
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login a user' })
  @ApiBody({ type: LoginDto })
  async login(@Body() body: { identifier: string; password: string }): Promise<any> {
    const tokenData = await this.usersService.login(body);
    return { message: 'Login successful', tokenData };
  }

  @ApiTags('Authentication')
  @Post('logout')
  @ApiOperation({ summary: 'Logout a user' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  @ApiBody({ type: LogoutDto })
  async logout(@Body() body: { refreshToken: string }): Promise<any> {
    await this.usersService.logout(body.refreshToken);
    return { message: 'Logout successful' };
  }

  @ApiTags('Authentication')
  @Post('reset-password/:id')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('JWT')
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

  @ApiTags('Authentication')
  @Post('refresh-token')
  @HttpCode(HttpStatus.OK)
  // @ApiBearerAuth('JWT')
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

  @ApiTags('Authentication')
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

  @ApiTags('Authentication')
  @Post('new-credentials')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get new password' })
  @ApiBody({
    schema: {
      properties: {
        identifier: {
          type: 'string',
          description: 'Username or Email',
          example: 'user@example.com'
        }
      }
    }
  })
  async generateNewPassword(@Body('identifier') identifier: string): Promise<any> {
    const credentials = await this.usersService.generateNewPassword(identifier);
    return { message: 'Credentials updated successfully', credentials };
  }

  @ApiTags('User Management')
  @Get()
  @ApiOperation({ summary: 'Find all users' })
  // @ApiBearerAuth()
  // @UseGuards(AuthGuard('jwt'))
  async findAll(
    @Query() pageOptionsDto: PageOptionsDto,
    @Query() searchUserDto: SearchUserDto
  ) {
    return await this.usersService.findAllUsers(pageOptionsDto, searchUserDto);
  }

  @ApiTags('User Management')
  @Get('by-status/:status')
  @ApiOperation({ summary: 'Find all users by status' })
  @ApiParam({
    name: 'status',
    enum: UserStatus,
    enumName: 'UserStatus',
    description: 'User status',
    required: true,
  })
  // @ApiBearerAuth('JWT')
  // @UseGuards(AuthGuard('jwt'))
  async findAllUsersByStatus(
    @Param('status') status: UserStatus,
    @Query() pageOptionsDto: PageOptionsDto
  ) {
    return await this.usersService.findAllUsersByStatus(status, pageOptionsDto);
  }

  @ApiTags('User Management')
  @Get('connected')
  @ApiOperation({ summary: 'Find all connected users' })
  // @UseGuards(AuthGuard('jwt'))
  findAllConnected() {
    return this.usersService.getConnectedUsers();
  }

  @ApiTags('User Management')
  @Get('by-id/:id')
  @ApiOperation({ summary: 'Find a user by ID' })
  // @ApiBearerAuth('JWT')
  // @UseGuards(AuthGuard('jwt'))
  findById(@Param('id') id: string) {
    return this.usersService.findUserById(id);
  }

  @ApiTags('User Management')
  @Get('by-username/:username')
  @ApiOperation({ summary: 'Find a user by username' })
  // @ApiBearerAuth('JWT')
  // @UseGuards(AuthGuard('jwt'))
  findByName(@Param('username') username: string) {
    return this.usersService.findUserByUsername(username);
  }

  @ApiTags('User Management')
  @Get('by-email/:email')
  @ApiOperation({ summary: 'Find a user by email' })
  // @ApiBearerAuth('JWT')
  // @UseGuards(AuthGuard('jwt'))
  findByEmail(@Param('email') email: string) {
    return this.usersService.findUserByEmail(email);
  }

  // ==============================
  // Realm Role Endpoints
  // ==============================

  @ApiTags('Roles Management')
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
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async createRealmRole(@Body() body: { roleName: string; description: string }): Promise<any> {
    await this.usersService.createRealmRole(body.roleName, body.description);
    return { message: `Role '${body.roleName}' created successfully.` };
  }

  @ApiTags('Roles Management')
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
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async updateRealmRole(
    @Param('roleName') roleName: string,
    @Body() body: { newName?: string; newDescription?: string }
  ): Promise<any> {
    await this.usersService.updateRealmRole(roleName, body.newName, body.newDescription);
    return { message: `Role '${roleName}' updated successfully.` };
  }

  @ApiTags('Roles Management')
  @Delete('roles/:roleName')
  @ApiParam({ name: 'roleName', description: 'RealmRole name to delete' })
  @ApiOperation({ summary: 'Delete a realm role' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async deleteRealmRole(@Param('roleName') roleName: string): Promise<any> {
    await this.usersService.deleteRealmRole(roleName);
    return { message: `Role '${roleName}' deleted successfully.` };
  }

  @ApiTags('Roles Management')
  @Get('roles')
  @ApiOperation({ summary: 'Get all Realm roles' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async getAllRealmRoles(): Promise<any[]> {
    return this.usersService.getAllRealmRoles();
  }

  @ApiTags('Roles Management')
  @Get('users-by-role/:role')
  @ApiOperation({ summary: 'Find all users by Realm role name' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  findByRealmRole(@Param('role') role: string) {
    return this.usersService.findAllUsersByRealmRole(role);
  }

  @ApiTags('Roles Management')
  @Get(':userId/roles')
  @ApiParam({ name: 'userId', description: 'User ID' })
  @ApiOperation({ summary: 'Get all Realm roles of a user' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async getUserRealmRoles(@Param('userId') userId: string): Promise<any[]> {
    return this.usersService.getUserRealmRoles(userId);
  }

  // ==============================
  // Group Endpoints
  // ==============================

  @ApiTags('Group Management')
  @Post('groups')
  @ApiOperation({ summary: 'Create a new group' })
  @ApiBody({ type: CreateGroupDto })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async createGroup(@Body() createGroupDto: CreateGroupDto): Promise<any> {
    await this.usersService.createGroup(createGroupDto.name, createGroupDto.attributes);
    return { message: `Group '${createGroupDto.name}' created successfully.` };
  }

  @ApiTags('Group Management')
  @Put('groups/:groupId')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiOperation({ summary: 'Update a group' })
  @ApiBody({ type: UpdateGrouprDto })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async updateGroup(
    @Param('groupId') groupId: string,
    @Body() updateGroupDto: UpdateGrouprDto,
  ): Promise<any> {
    await this.usersService.updateGroup(groupId, updateGroupDto.name, updateGroupDto.attributes);
    return { message: `Group '${groupId}' updated successfully.` };
  }

  @ApiTags('Group Management')
  @Delete('groups/:groupId')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiOperation({ summary: 'Delete a group' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async deleteGroup(@Param('groupId') groupId: string): Promise<any> {
    await this.usersService.deleteGroup(groupId);
    return { message: `Group '${groupId}' deleted successfully.` };
  }

  @ApiTags('Group Management')
  @Get('groups')
  @ApiOperation({ summary: 'Get all groups' })
  // @ApiBearerAuth('JWT')
  // @UseGuards(AuthGuard('jwt'))
  async getAllGroups(): Promise<any[]> {
    return this.usersService.getAllGroups();
  }

  @ApiTags('Group Management')
  @Get('groups/:groupId')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiOperation({ summary: 'Get group details by ID' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async getGroupById(@Param('groupId') groupId: string): Promise<any> {
    return this.usersService.getGroupById(groupId);
  }

  @ApiTags('Group Management')
  @Get('groups/by-name/:groupName')
  @ApiParam({ name: 'groupName', description: 'Group name' })
  @ApiOperation({ summary: 'Get group details by name' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async getGroupByName(@Param('groupName') groupName: string): Promise<any> {
    return this.usersService.getGroupByName(groupName);
  }

  @ApiTags('Group Management')
  @Get(':userId/groups')
  @ApiParam({ name: 'userId', description: 'User ID' })
  @ApiOperation({ summary: 'Get all groups for a user' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async getUserGroups(@Param('userId') userId: string): Promise<any[]> {
    return this.usersService.getUserGroups(userId);
  }

  @ApiTags('Group Management')
  @Put('groups/:groupId/users/:userId')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiParam({ name: 'userId', description: 'User Database ID' })
  @ApiOperation({ summary: 'Add a user to a group' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async addUserToGroup(@Param('userId') userId: string, @Param('groupId') groupId: string): Promise<any> {
    await this.usersService.addUserToGroup(userId, groupId);
    return { message: `User '${userId}' added to group '${groupId}' successfully.` };
  }

  @ApiTags('Group Management')
  @Delete('groups/:groupId/users/:userId')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiParam({ name: 'userId', description: 'User Database ID' })
  @ApiOperation({ summary: 'Remove a user from a group' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async removeUserFromGroup(@Param('userId') userId: string, @Param('groupId') groupId: string): Promise<any> {
    await this.usersService.removeUserFromGroup(userId, groupId);
    return { message: `User '${userId}' removed from group '${groupId}' successfully.` };
  }

  @ApiTags('Group Management')
  @Get('groups/:groupId/users')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiOperation({ summary: 'Get all users in a group' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async getAllUsersFromGroup(@Param('groupId') groupId: string): Promise<any[]> {
    return this.usersService.getAllUsersFromGroup(groupId);
  }

  @ApiTags('Group Management')
  @Get('groups/by-name/:groupName/users')
  @ApiParam({ name: 'groupName', description: 'Group name' })
  @ApiOperation({ summary: 'Get all users in a group by group name' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async getAllUsersFromGroupByName(@Param('groupName') groupName: string): Promise<any[]> {
    return this.usersService.getAllUsersFromNameGroup(groupName);
  }

  @ApiTags('Group Management')
  @Post('groups/:groupId/roles/:roleName')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiParam({ name: 'roleName', description: 'Role name' })
  @ApiOperation({ summary: 'Add a role to a group' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async addRoleToGroup(@Param('groupId') groupId: string, @Param('roleName') roleName: string): Promise<any> {
    await this.usersService.addRoleToGroup(groupId, roleName);
    return { message: `Role '${roleName}' added to group '${groupId}' successfully.` };
  }

  @ApiTags('Group Management')
  @Delete('groups/:groupId/roles/:roleName')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiParam({ name: 'roleName', description: 'Role name' })
  @ApiOperation({ summary: 'Remove a role from a group' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async removeRoleFromGroup(@Param('groupId') groupId: string, @Param('roleName') roleName: string): Promise<any> {
    await this.usersService.removeRoleFromGroup(groupId, roleName);
    return { message: `Role '${roleName}' removed from group '${groupId}' successfully.` };
  }

  @ApiTags('Group Management')
  @Get('groups/:groupId/roles')
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiOperation({ summary: 'Get roles assigned to a group' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async getGroupRoles(@Param('groupId') groupId: string): Promise<any> {
    return this.usersService.getGroupRoles(groupId);
  }




  // ==============================
  // Client Role Endpoints
  // ==============================




  @ApiTags('Client Roles')
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
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async createClientRole(@Body() body: { roleName: string; description: string }): Promise<any> {
    await this.usersService.createClientRole(body.roleName, body.description);
    return { message: `Client role '${body.roleName}' created successfully.` };
  }

  @ApiTags('Client Roles')
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
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async updateClientRole(
    @Param('roleName') roleName: string,
    @Body() body: { newName?: string; newDescription?: string }
  ): Promise<any> {
    await this.usersService.updateClientRole(roleName, body.newName, body.newDescription);
    return { message: `Client role '${roleName}' updated successfully.` };
  }

  @ApiTags('Client Roles')
  @Get('client-roles')
  @ApiOperation({ summary: 'Get all Client roles' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async getAllClientRoles(): Promise<any[]> {
    return this.usersService.getAllClientRoles();
  }

  @ApiTags('Client Roles')
  @Delete('client-roles/:roleName')
  @ApiParam({ name: 'roleName', description: 'Client role name to delete' })
  @ApiOperation({ summary: 'Delete a Client role' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async deleteClientRole(@Param('roleName') roleName: string): Promise<any> {
    await this.usersService.deleteClientRole(roleName);
    return { message: `Client role '${roleName}' deleted successfully.` };
  }

  @ApiTags('Client Roles')
  @Post('client-roles/:roleName/groups/:groupId')
  @ApiParam({ name: 'roleName', description: 'Client role name' })
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiOperation({ summary: 'Add a Client role to a group' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async addClientRoleToGroup(
    @Param('groupId') groupId: string,
    @Param('roleName') roleName: string
  ): Promise<any> {
    await this.usersService.addClientRoleToGroup(groupId, roleName);
    return { message: `Client role '${roleName}' added to group '${groupId}' successfully.` };
  }

  @ApiTags('Client Roles')
  @Delete('client-roles/:roleName/groups/:groupId')
  @ApiParam({ name: 'roleName', description: 'Client role name' })
  @ApiParam({ name: 'groupId', description: 'Group ID' })
  @ApiOperation({ summary: 'Remove a Client role from a group' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async removeClientRoleFromGroup(
    @Param('groupId') groupId: string,
    @Param('roleName') roleName: string
  ): Promise<any> {
    await this.usersService.removeClientRoleFromGroup(groupId, roleName);
    return { message: `Client role '${roleName}' removed from group '${groupId}' successfully.` };
  }

  @ApiTags('Client Roles')
  @Post('client-roles/:roleName/users/:userId')
  @ApiParam({ name: 'roleName', description: 'Client role name' })
  @ApiParam({ name: 'userId', description: 'User ID' })
  @ApiOperation({ summary: 'Add a Client role to a user' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async addClientRoleToUser(
    @Param('userId') userId: string,
    @Param('roleName') roleName: string
  ): Promise<any> {
    await this.usersService.addClientRoleToUser(userId, roleName);
    return { message: `Client role '${roleName}' added to user '${userId}' successfully.` };
  }

  @ApiTags('Client Roles')
  @Delete('client-roles/:roleName/users/:userId')
  @ApiParam({ name: 'roleName', description: 'Client role name' })
  @ApiParam({ name: 'userId', description: 'User ID' })
  @ApiOperation({ summary: 'Remove a Client role from a user' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async removeClientRoleFromUser(
    @Param('userId') userId: string,
    @Param('roleName') roleName: string
  ): Promise<any> {
    await this.usersService.removeClientRoleFromUser(userId, roleName);
    return { message: `Client role '${roleName}' removed from user '${userId}' successfully.` };
  }

  @ApiTags('Client Roles')
  @Get('client-roles/users/:userId')
  @ApiParam({ name: 'userId', description: 'User ID' })
  @ApiOperation({ summary: 'Find all Client roles by User ID' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async findClientRolesByUserId(@Param('userId') userId: string): Promise<any[]> {
    return this.usersService.findClientRolesByUserId(userId);
  }

  @ApiTags('Client Roles')
  @Get('client-roles/:roleName/users')
  @ApiParam({ name: 'roleName', description: 'Client role name' })
  @ApiOperation({ summary: 'Find all users by Client role name' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async findUsersByClientRole(@Param('roleName') roleName: string): Promise<any[]> {
    return this.usersService.findUsersByClientRole(roleName);
  }




  // ==============================
  // Client Management Endpoints
  // ==============================




  @ApiTags('Client Management')
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
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async createClient(@Body() clientData: any): Promise<any> {
    return this.usersService.createClient(clientData);
  }

  @ApiTags('Client Management')
  @Delete('clients/:clientId')
  @ApiParam({ name: 'clientId', description: 'Client ID' })
  @ApiOperation({ summary: 'Delete a client' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async deleteClient(@Param('clientId') clientId: string): Promise<void> {
    return this.usersService.deleteClient(clientId);
  }

  @ApiTags('Client Management')
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
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async updateClient(
    @Param('clientId') clientId: string,
    @Body() clientData: any,
  ): Promise<any> {
    return this.usersService.updateClient(clientId, clientData);
  }

  @ApiTags('Client Management')
  @Get('clients/by-name/:clientName')
  @ApiParam({ name: 'clientName', description: 'Client Name' })
  @ApiOperation({ summary: 'Get a client by name: ClientID' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async getClientByName(@Param('clientName') clientName: string): Promise<any> {
    return this.usersService.getClientByName(clientName);
  }

  @ApiTags('Client Management')
  @Get('clients/:clientId')
  @ApiParam({ name: 'clientId', description: 'Client ID' })
  @ApiOperation({ summary: 'Get a client by ID: ahahaj984-df98-df98-df98-df98-df98' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async getClientById(@Param('clientId') clientId: string): Promise<any> {
    return this.usersService.getClientById(clientId);
  }

  @ApiTags('Client Management')
  @Get('clients')
  @ApiOperation({ summary: 'Get all clients' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async getAllClients(): Promise<any[]> {
    return this.usersService.getAllClients();
  }

  @ApiTags('Client Management')
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
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async addClientRole(
    @Param('clientId') clientId: string,
    @Body() body: { roleName: string; description: string },
  ): Promise<void> {
    return this.usersService.addClientRole(clientId, body.roleName, body.description);
  }

  @ApiTags('Client Management')
  @Delete('clients/:clientId/roles/:roleName')
  @ApiParam({ name: 'clientId', description: 'Client ID' })
  @ApiParam({ name: 'roleName', description: 'Role Name' })
  @ApiOperation({ summary: 'Remove a role from a client' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async removeClientRole(
    @Param('clientId') clientId: string,
    @Param('roleName') roleName: string,
  ): Promise<void> {
    return this.usersService.removeClientRole(clientId, roleName);
  }

  @ApiTags('Client Management')
  @Post('clients/:clientId/regenerate-secret')
  @ApiParam({ name: 'clientId', description: 'Client ID' })
  @ApiOperation({ summary: 'Regenerate client secret' })
  @ApiBearerAuth('JWT')
  @UseGuards(AuthGuard('jwt'))
  async regenerateClientSecret(@Param('clientId') clientId: string): Promise<any> {
    return this.usersService.regenerateClientSecret(clientId);
  }

}