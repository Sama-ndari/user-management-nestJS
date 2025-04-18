import { Controller, Post, Body, Get, Request, Patch, Delete, Param, Put, HttpCode, HttpStatus } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto, ResetPasswordDto } from './dto/create-user.dto';
import { Roles } from 'nest-keycloak-connect';
import { ApiBody, ApiOperation, ApiParam, ApiTags } from '@nestjs/swagger';
import { UpdateUserDto } from './dto/update-user.dto';
import { LoginDto } from './dto/login.dto';
import { LogoutDto } from './dto/logout.dto';

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
  findAll() {
    return this.usersService.findAllUsers();
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