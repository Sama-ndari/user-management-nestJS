import { ApiProperty } from "@nestjs/swagger";
import { PageMetaDtoParameters } from "../page-meta-dto-parameters/page-meta-dto-parameters";

export class PageMetaDto {
    @ApiProperty()
    readonly page: number;
  
    @ApiProperty()
    readonly take: number;
  
    @ApiProperty()
    readonly itemCount: number;
  
    @ApiProperty()
    readonly pageCount: number;

    constructor({ pageOptionsDto, itemCount }: PageMetaDtoParameters) {
        this.page = pageOptionsDto.page ?? 1; // Default to 1 if undefined
        this.take = pageOptionsDto.take ?? 10; // Default to 10 if undefined
        this.itemCount = itemCount;
        this.pageCount = Math.ceil(this.itemCount / this.take);
      }
    }
