import { ForbiddenException, Injectable } from '@nestjs/common';
import { CreateBookmarkDto, EditBookmarkDto } from './dto';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class BookmarkService {
  constructor(
    private prismaService: PrismaService
  ) {}

  getBookmarks(userId: number) {
    return this.prismaService.bookmark.findMany({
      where: {
        userId
      },
    })
  }

  getBookmarkById(userId: number, bookmarkId: number) {
    return this.prismaService.bookmark.findFirst({
      where: {
        id: bookmarkId,
        userId
      },
    })
  }

  async createBookmark(userId: number, dto: CreateBookmarkDto) {
    const bookmark = await this.prismaService.bookmark.create({
      data: {
        userId,
        ...dto
      }
    })

    return bookmark;
  }

  async editBookmarkById(userId: number, bookmarkId: number, dto: EditBookmarkDto) {
    // ger the bookmark by id
    const bookmark = await this.prismaService.bookmark.findUnique({
      where: {
        id: bookmarkId
      }
    })

    // check if user owns the bookmark
    if (!bookmark || bookmark.userId !== userId) {
      throw new ForbiddenException('Access to resources denied')
    }

    return this.prismaService.bookmark.update({
      where: {
        id: bookmarkId
      },
      data: {
        ...dto
      }
    })
  }

  async deleteBookmarkById(userId: number, bookmarkId: number) {
    const bookmark = await this.prismaService.bookmark.findUnique({
      where: {
        id: bookmarkId
      }
    })

    // check if user owns the bookmark
    if (!bookmark || bookmark.userId !== userId) {
      throw new ForbiddenException('Access to resources denied')
    }

    return this.prismaService.bookmark.delete({
      where: {
        id: bookmarkId
      }
    })
  }
}
