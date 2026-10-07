import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import type { Request, Response } from 'express';
import type { LoginDetails } from 'src/services/auth.service.js';
import { Endpoint, HistoryBuilder } from 'src/decorators.js';
import { type AuthDto, LoginResponseDto } from 'src/dtos/auth.dto.js';
import {
  PasskeyAuthenticationFinishDto,
  PasskeyAuthenticationOptionsDto,
  PasskeyRegistrationFinishDto,
  PasskeyRegistrationOptionsDto,
  PasskeyResponseDto,
  PasskeySearchDto,
  PasskeyUpdateDto,
} from 'src/dtos/passkey.dto.js';
import { ApiTag, AuthType, ImmichCookie, Permission } from 'src/enum.js';
import { Auth, Authenticated, GetLoginDetails } from 'src/middleware/auth.guard.js';
import { PasskeyService } from 'src/services/passkey.service.js';
import { respondWithCookie, respondWithoutCookie } from 'src/utils/response.js';
import { UUIDParamDto } from 'src/validation.js';

@ApiTags(ApiTag.Passkeys)
@Controller('passkeys')
export class PasskeyController {
  constructor(private service: PasskeyService) {}

  @Post('registration/start')
  @Authenticated({ permission: Permission.PasskeyCreate })
  @HttpCode(HttpStatus.OK)
  @Endpoint({
    summary: 'Start passkey registration',
    description: 'Generate the options used by the browser to create a new passkey for the current user.',
    history: HistoryBuilder.v4().alpha('v4.0.0'),
  })
  async startRegistration(
    @Req() request: Request,
    @Res({ passthrough: true }) res: Response,
    @Auth() auth: AuthDto,
    @GetLoginDetails() loginDetails: LoginDetails,
  ): Promise<PasskeyRegistrationOptionsDto> {
    const options = await this.service.startRegistration(auth, request.headers);
    return respondWithCookie(res, options, {
      isSecure: loginDetails.isSecure,
      values: [{ key: ImmichCookie.PasskeyChallenge, value: options.challenge }],
    });
  }

  @Post('registration/finish')
  @Authenticated({ permission: Permission.PasskeyCreate })
  @Endpoint({
    summary: 'Finish passkey registration',
    description: 'Verify the response from the authenticator and save the new passkey for the current user.',
    history: HistoryBuilder.v4().alpha('v4.0.0'),
  })
  async finishRegistration(
    @Req() request: Request,
    @Res({ passthrough: true }) res: Response,
    @Auth() auth: AuthDto,
    @Body() dto: PasskeyRegistrationFinishDto,
    @GetLoginDetails() loginDetails: LoginDetails,
  ): Promise<PasskeyResponseDto> {
    const passkey = await this.service.finishRegistration(auth, dto, request.headers, loginDetails);
    return respondWithoutCookie(res, passkey, [ImmichCookie.PasskeyChallenge]);
  }

  @Post('authentication/start')
  @Authenticated({ public: true })
  @HttpCode(HttpStatus.OK)
  @Endpoint({
    summary: 'Start passkey authentication',
    description: 'Generate the options used by the browser to sign in with a passkey.',
    history: HistoryBuilder.v4().alpha('v4.0.0'),
  })
  async startAuthentication(
    @Req() request: Request,
    @Res({ passthrough: true }) res: Response,
    @GetLoginDetails() loginDetails: LoginDetails,
  ): Promise<PasskeyAuthenticationOptionsDto> {
    const options = await this.service.startAuthentication(request.headers);
    return respondWithCookie(res, options, {
      isSecure: loginDetails.isSecure,
      values: [{ key: ImmichCookie.PasskeyChallenge, value: options.challenge }],
    });
  }

  @Post('authentication/finish')
  @Authenticated({ public: true })
  @Endpoint({
    summary: 'Finish passkey authentication',
    description: 'Verify the response from the authenticator and receive a session token.',
    history: HistoryBuilder.v4().alpha('v4.0.0'),
  })
  async finishAuthentication(
    @Req() request: Request,
    @Res({ passthrough: true }) res: Response,
    @Body() dto: PasskeyAuthenticationFinishDto,
    @GetLoginDetails() loginDetails: LoginDetails,
  ): Promise<LoginResponseDto> {
    const body = await this.service.finishAuthentication(dto, request.headers, loginDetails);
    res.clearCookie(ImmichCookie.PasskeyChallenge);
    return respondWithCookie(res, body, {
      isSecure: loginDetails.isSecure,
      values: [
        { key: ImmichCookie.AccessToken, value: body.accessToken },
        { key: ImmichCookie.AuthType, value: AuthType.Passkey },
        { key: ImmichCookie.IsAuthenticated, value: 'true' },
      ],
    });
  }

  @Get()
  @Authenticated({ permission: Permission.PasskeyRead })
  @Endpoint({
    summary: 'Search passkeys',
    description: 'Search the passkeys of the current user.',
    history: HistoryBuilder.v4().alpha('v4.0.0'),
  })
  searchPasskeys(@Auth() auth: AuthDto, @Query() dto: PasskeySearchDto): Promise<PasskeyResponseDto[]> {
    return this.service.search(auth, dto);
  }

  @Get(':id')
  @Authenticated({ permission: Permission.PasskeyRead })
  @Endpoint({
    summary: 'Retrieve a passkey',
    description: 'Retrieve a passkey by its ID. The current user must own this passkey.',
    history: HistoryBuilder.v4().alpha('v4.0.0'),
  })
  getPasskey(@Auth() auth: AuthDto, @Param() { id }: UUIDParamDto): Promise<PasskeyResponseDto> {
    return this.service.get(auth, id);
  }

  @Patch(':id')
  @Authenticated({ permission: Permission.PasskeyUpdate })
  @Endpoint({
    summary: 'Update a passkey',
    description: 'Update the name of a passkey by its ID. The current user must own this passkey.',
    history: HistoryBuilder.v4().alpha('v4.0.0'),
  })
  updatePasskey(
    @Auth() auth: AuthDto,
    @Param() { id }: UUIDParamDto,
    @Body() dto: PasskeyUpdateDto,
  ): Promise<PasskeyResponseDto> {
    return this.service.update(auth, id, dto);
  }

  @Delete(':id')
  @Authenticated({ permission: Permission.PasskeyDelete })
  @HttpCode(HttpStatus.NO_CONTENT)
  @Endpoint({
    summary: 'Delete a passkey',
    description: 'Delete a passkey by its ID. The current user must own this passkey.',
    history: HistoryBuilder.v4().alpha('v4.0.0'),
  })
  deletePasskey(@Auth() auth: AuthDto, @Param() { id }: UUIDParamDto): Promise<void> {
    return this.service.delete(auth, id);
  }
}
