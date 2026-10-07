import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { parse } from 'cookie';
import { IncomingHttpHeaders } from 'node:http';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import type { LoginDetails } from 'src/services/auth.service.js';
import { AuthDto, LoginResponseDto } from 'src/dtos/auth.dto.js';
import {
  PasskeyAuthenticationFinishDto,
  PasskeyAuthenticationOptionsDto,
  PasskeyRegistrationFinishDto,
  PasskeyRegistrationOptionsDto,
  PasskeyResponseDto,
  PasskeySearchDto,
  PasskeyUpdateDto,
  mapPasskey,
} from 'src/dtos/passkey.dto.js';
import { ImmichCookie, Permission } from 'src/enum.js';
import { BaseService } from 'src/services/base.service.js';
import { findOrFail } from 'src/utils/misc.js';
import { getPasskeyName } from 'src/utils/passkey.js';

const RP_NAME = 'Immich';

@Injectable()
export class PasskeyService extends BaseService {
  async startRegistration(auth: AuthDto, headers: IncomingHttpHeaders): Promise<PasskeyRegistrationOptionsDto> {
    await this.requireEnabled();

    const { rpId } = this.getRelyingParty(headers);
    const passkeys = await this.passkeyRepository.search({ userId: auth.user.id });

    return this.webAuthnRepository.generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: rpId,
      userID: new TextEncoder().encode(auth.user.id),
      userName: auth.user.email,
      userDisplayName: auth.user.name,
      attestationType: 'none',
      excludeCredentials: passkeys.map(({ credentialId, transports }) => ({ id: credentialId, transports })),
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    });
  }

  async finishRegistration(
    auth: AuthDto,
    dto: PasskeyRegistrationFinishDto,
    headers: IncomingHttpHeaders,
    loginDetails: LoginDetails,
  ): Promise<PasskeyResponseDto> {
    await this.requireEnabled();

    const { rpId, origin } = this.getRelyingParty(headers);
    const expectedChallenge = this.getChallenge(headers);

    const result = await this.webAuthnRepository
      .verifyRegistrationResponse({
        response: dto.response as RegistrationResponseJSON,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpId,
      })
      .catch((error: Error) => {
        this.logger.warn(`Passkey registration failed for user ${auth.user.id}: ${error.message}`);
        throw new BadRequestException('Passkey registration failed');
      });

    if (!result.verified) {
      throw new BadRequestException('Passkey registration failed');
    }

    const { aaguid, credential, credentialBackedUp, credentialDeviceType } = result.registrationInfo;

    const duplicate = await this.passkeyRepository.getByCredentialId(credential.id);
    if (duplicate) {
      throw new BadRequestException('Passkey is already registered');
    }

    const passkey = await this.passkeyRepository.create({
      userId: auth.user.id,
      name: dto.name || getPasskeyName(aaguid, loginDetails),
      credentialId: credential.id,
      publicKey: Buffer.from(credential.publicKey),
      counter: credential.counter,
      transports: credential.transports ?? [],
      backedUp: credentialBackedUp,
      deviceType: credentialDeviceType,
    });

    return mapPasskey(passkey);
  }

  async startAuthentication(headers: IncomingHttpHeaders): Promise<PasskeyAuthenticationOptionsDto> {
    await this.requireLoginEnabled();

    const { rpId } = this.getRelyingParty(headers);

    return this.webAuthnRepository.generateAuthenticationOptions({ rpID: rpId, userVerification: 'required' });
  }

  async finishAuthentication(
    dto: PasskeyAuthenticationFinishDto,
    headers: IncomingHttpHeaders,
    loginDetails: LoginDetails,
  ): Promise<LoginResponseDto> {
    await this.requireLoginEnabled();

    const { rpId, origin } = this.getRelyingParty(headers);
    const expectedChallenge = this.getChallenge(headers);

    const passkey = await this.passkeyRepository.getByCredentialId(dto.response.id);
    const userHandle = dto.response.response.userHandle;
    const userId = userHandle ? Buffer.from(userHandle, 'base64url').toString() : undefined;
    if (!passkey || (userId && userId !== passkey.userId)) {
      this.logger.warn(`Failed passkey login attempt from ip address ${loginDetails.clientIp}`);
      throw new UnauthorizedException('Invalid passkey');
    }

    const result = await this.webAuthnRepository
      .verifyAuthenticationResponse({
        response: dto.response as AuthenticationResponseJSON,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpId,
        credential: {
          id: passkey.credentialId,
          publicKey: new Uint8Array(passkey.publicKey),
          counter: passkey.counter,
          transports: passkey.transports,
        },
      })
      .catch((error: Error) => {
        this.logger.warn(`Failed passkey login attempt from ip address ${loginDetails.clientIp}: ${error.message}`);
        throw new UnauthorizedException('Invalid passkey');
      });

    if (!result.verified) {
      throw new UnauthorizedException('Invalid passkey');
    }

    const user = await this.userRepository.get(passkey.userId, {});
    if (!user) {
      throw new UnauthorizedException('Invalid passkey');
    }

    await this.passkeyRepository.update(passkey.id, {
      counter: result.authenticationInfo.newCounter,
      usedAt: new Date(),
    });

    return this.createLoginResponse(user, loginDetails);
  }

  async search(auth: AuthDto, dto: PasskeySearchDto): Promise<PasskeyResponseDto[]> {
    const passkeys = await this.passkeyRepository.search({ id: dto.id, userId: auth.user.id });
    return passkeys.map((passkey) => mapPasskey(passkey));
  }

  async get(auth: AuthDto, id: string): Promise<PasskeyResponseDto> {
    await this.requireAccess({ auth, permission: Permission.PasskeyRead, ids: [id] });
    const passkey = await findOrFail(() => this.passkeyRepository.get(id), 'Passkey');
    return mapPasskey(passkey);
  }

  async update(auth: AuthDto, id: string, dto: PasskeyUpdateDto): Promise<PasskeyResponseDto> {
    await this.requireAccess({ auth, permission: Permission.PasskeyUpdate, ids: [id] });
    const passkey = await this.passkeyRepository.update(id, { name: dto.name });
    return mapPasskey(passkey);
  }

  async delete(auth: AuthDto, id: string): Promise<void> {
    await this.requireAccess({ auth, permission: Permission.PasskeyDelete, ids: [id] });
    await this.passkeyRepository.delete(id);
  }

  private async requireEnabled() {
    const { passkey } = await this.getConfig({ withCache: false });
    if (!passkey.enabled) {
      throw new BadRequestException('Passkeys are disabled');
    }
  }

  private async requireLoginEnabled() {
    const { passkey } = await this.getConfig({ withCache: false });
    if (!passkey.enabled) {
      throw new UnauthorizedException('Passkey login has been disabled');
    }
  }

  private getRelyingParty(headers: IncomingHttpHeaders) {
    const origin = headers.origin;
    if (!origin) {
      throw new BadRequestException('Origin header is missing');
    }

    try {
      return { origin, rpId: new URL(origin).hostname };
    } catch {
      throw new BadRequestException('Origin header is invalid');
    }
  }

  private getChallenge(headers: IncomingHttpHeaders) {
    const cookies = parse(headers.cookie || '');
    const challenge = cookies[ImmichCookie.PasskeyChallenge];
    if (!challenge) {
      throw new BadRequestException('Passkey challenge is missing');
    }

    return challenge;
  }
}
