import { Controller } from '@nestjs/common';
import { UseGuards } from '@nestjs/common';
import { Get, Patch } from '@nestjs/common';
import { User } from '@prisma/client';
import { GetUser } from '../../src/auth/decorator';
import { JwtGuard } from '../../src/auth/guard';

@Controller('users')
@UseGuards(JwtGuard)
export class UserController {

  @Get('me')
  getMe(@GetUser() user: User) {
    return user;
  }

  @Patch()
  editUser() {}
}
