import { ApiProperty, PartialType } from '@nestjs/swagger';
import { IsNotEmpty } from 'class-validator';

export class Attributes {
    @ApiProperty({
        description: 'Description of the group',
        example: 'Group for admin users',
    })
    description: string;

    @ApiProperty({
        description: 'User who created the group',
        example: 'system',
    })
    createdBy: string;

    @ApiProperty({
        description: 'Indicates if the group is active',
        example: true,
    })
    isActive: boolean;

    @ApiProperty({
        description: 'Timestamp when the group was created',
    })
    createdAt: string;

    @ApiProperty({
        description: 'Timestamp when the group was last updated',
    })
    updatedAt: string;
}

export class CreateGroupDto {
    @ApiProperty({
        description: 'Name of the group',
        example: 'Admin',
    })
    @IsNotEmpty()
    name: string;

    @ApiProperty({
        description: 'Attributes of the group',
        example: {
            description: 'Group for admin users',
            createdBy: 'System',
            isActive: true,
        },
        required: false,
    })
    attributes?: Attributes = {
        description: 'Group for users',
        createdBy: 'system',
        isActive: true,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
    };
}

export class UpdateGrouprDto extends PartialType(CreateGroupDto) {}