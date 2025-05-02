import { ApiProperty } from "@nestjs/swagger";
import { IsArray, IsNumber, IsString } from "class-validator";
import { PageMetaDto } from "../page-meta-dto/page-meta-dto";

export class PageDto<T> {
    @IsNumber()
    @ApiProperty({default: 200})
    readonly statusCode : number
    @IsString()
    @ApiProperty({default: 'success'})
    readonly message : string
    @IsArray()
    @ApiProperty({ isArray: true })
    readonly data: T[];
    @ApiProperty({ type: () => PageMetaDto })
    readonly meta: PageMetaDto;

    constructor(data: T[], meta: PageMetaDto) {
        this.statusCode = 200
        this.message = 'success'
        this.data = data;
        this.meta = meta;
    }
}
