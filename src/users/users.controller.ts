//src/users/users.controller.ts
import { Controller, Post, Body, Get, Request, Patch, Delete, Param, Put, HttpCode, HttpStatus, Query } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto, ResetPasswordDto } from './dto/create-user.dto';
import { Roles } from 'nest-keycloak-connect';
import { ApiBody, ApiOperation, ApiParam, ApiTags } from '@nestjs/swagger';
import { UpdateUserDto } from './dto/update-user.dto';
import { LoginDto } from './dto/login.dto';
import { LogoutDto } from './dto/logout.dto';
import { PageOptionsDto } from 'src/common/page-options-dto';

@ApiTags('User Waangu Marketplace')
@Controller('users')
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
  ) { }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login a user' })
  @ApiBody({ type: LoginDto })
  async login(@Body() body: { identifier: string; password: string }): Promise<any> {
    const tokenData = await this.usersService.login(body);
    return { message: 'Login successful', tokenData };
  }
  
  @Post('decode-token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Decode an access token' })
  @ApiBody({ 
    schema: { 
      properties: { 
        accessToken: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' } 
      } 
    } 
  })
  async decodeToken(@Body() body: { accessToken: string }): Promise<any> {
    const decodedData = await this.usersService.decodeToken(body.accessToken);
    return { message: 'Token decoded successfully', decodedData };
  }

  @Post('logout')
  @ApiOperation({ summary: 'Logout a user' })
  @ApiBody({ type: LogoutDto })
  async logout(@Body() body: { refreshToken: string }): Promise<any> {
    await this.usersService.logout(body.refreshToken);
    return { message: 'Logout successful' };
  }

  @Post()
  @ApiOperation({ summary: 'Create a new user' })
  @ApiBody({ type: CreateUserDto })
  @Roles({ roles: ['Admin'] }) // Only Admins can create users
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.createUser(createUserDto);
  }

  @Put('/:id')
  @ApiParam({ name: 'id', description: 'User ID' })
  @ApiBody({ type: UpdateUserDto })
  @ApiOperation({ summary: 'update a user' })
  @Roles({ roles: ['Admin'] }) // Only Admins can update users
  update(@Param('id') id: string, @Body() updateData: UpdateUserDto) {
    return this.usersService.updateUser(id, updateData);
  }

  @Post('reset-password/:id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'reset a user password' })
  @ApiBody({ type: ResetPasswordDto})
  async resetPassword(
    @Param('id') id: string,
    @Body() body: ResetPasswordDto,
  ): Promise<any> {
    const updatedUser = await this.usersService.resetPassword(id, body.newPassword);
    return { message: 'Password reset successfully', user: updatedUser };
  }

  @Post('refresh-token')
  @HttpCode(HttpStatus.OK)
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

  @Post('roles')
  @ApiOperation({ summary: 'Create a new role' })
  @ApiBody({ 
    schema: { 
      properties: { 
        roleName: { type: 'string', example: 'Admin' },
        description: { type: 'string', example: 'Administrator role with full access' }
      } 
    } 
  })
  @Roles({ roles: ['Admin'] }) // Only Admins can create roles
  async createRole(@Body() body: { roleName: string; description: string }): Promise<any> {
    await this.usersService.createRole(body.roleName, body.description);
    return { message: `Role '${body.roleName}' created successfully.` };
  }

  @Delete('roles/:roleName')
  @ApiParam({ name: 'roleName', description: 'Role name to delete' })
  @ApiOperation({ summary: 'Delete a role' })
  @Roles({ roles: ['Admin'] }) // Only Admins can delete roles
  async deleteRole(@Param('roleName') roleName: string): Promise<any> {
    await this.usersService.deleteRole(roleName);
    return { message: `Role '${roleName}' deleted successfully.` };
  }

  @Put('roles/:roleName')
  @ApiParam({ name: 'roleName', description: 'Role name to update' })
  @ApiBody({ 
    schema: { 
      properties: { 
        newName: { type: 'string', example: 'UpdatedRoleName' },
        newDescription: { type: 'string', example: 'Updated description for the role' }
      } 
    } 
  })
  @ApiOperation({ summary: 'Update a role name or description' })
  @Roles({ roles: ['Admin'] }) // Only Admins can update roles
  async updateRole(
    @Param('roleName') roleName: string, 
    @Body() body: { newName?: string; newDescription?: string }
  ): Promise<any> {
    await this.usersService.updateRole(roleName, body.newName, body.newDescription);
    return { message: `Role '${roleName}' updated successfully.` };
  }

  @Put('/:id/assign-role/:role')
  @ApiParam({ name: 'id', description: 'User ID' })
  @ApiParam({ name: 'role', description: 'Role name' })
  @ApiOperation({ summary: 'assign a role' })
  @Roles({ roles: ['Admin','Customer'] }) // Only Admins can assign roles
  async assignRole(@Param('id') userId: string, @Param('role') role: string) {
    await this.usersService.assignRole(userId, role);
  }

  @Put('/:id/deassign-role/:role')
  @ApiParam({ name: 'id', description: 'User ID' })
  @ApiParam({ name: 'role', description: 'Role name' })
  @ApiOperation({ summary: 'deAssignRole a role' })
  @Roles({ roles: ['Admin'] }) // Only Admins can assign roles
  async deAssignRole(@Param('id') userId: string, @Param('role') role: string) {
    await this.usersService.deAssignRole(userId, role);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete a new user' })
  @Roles({ roles: ['Admin'] }) // Only Admins can delete users
  async delete(@Param('id') id: string) {
    return this.usersService.deleteUser(id);
  }

  // @Get('profile')
  // @Roles({ roles: ['Customer', 'Merchant', 'Commissionaire'] }) // Accessible to non-Admin roles
  // getProfile(@Request() req) {
  //   return req.user; // Returns user info from the JWT token
  // }

  @Get('users-by-role/:role')
  @ApiOperation({ summary: 'Find all users by role name' })
  @Roles({ roles: ['Admin'] })  // Only accessible by users with the admin role.
  findByRole(@Param('role') role: string) {
    return this.usersService.findAllUsersByRole(role);
  }

  @Get()
  @ApiOperation({ summary: 'Find all users' })
  @Roles({ roles: ['Admin'] })  // Only accessible by users with the admin role.
  findAll(@Query() pageOptionsDto: PageOptionsDto) {
    return this.usersService.findAllUsers(pageOptionsDto);
  }

  @Get('connected')
  @ApiOperation({ summary: 'Find all connected users' })
  @Roles({ roles: ['Admin'] })  // Only accessible by users with the admin role.
  findAllConnected() {
    return this.usersService.getConnectedUsers();
  }

  @Get('by-id/:id')
  @ApiOperation({ summary: 'Find a user by ID' })
  @Roles({ roles: ['Admin'] })  // Only accessible by users with the admin role.
  findById(@Param('id') id: string) {
    return this.usersService.findUserById(id);
  }

  @Get('by-username/:username')
  @ApiOperation({ summary: 'Find a user by username' })
  @Roles({ roles: ['Admin'] })  // Only accessible by users with the admin role.
  findByName(@Param('username') username: string) {
    return this.usersService.findUserByUsername(username);
  }

  @Get('by-email/:email')
  @ApiOperation({ summary: 'Find a user by email' })
  @Roles({ roles: ['Admin'] })  // Only accessible by users with the admin role.
  findByEmail(@Param('email') email: string) {
    return this.usersService.findUserByEmail(email);
  }
}