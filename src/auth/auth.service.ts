import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { randomUUID } from 'crypto';
import { LoginAuthDto } from './dto/login-auth.dto';
import { RegisterAuthDto } from './dto/register-auth.dto';

type AuthUser = {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
};

export type AuthResponse = {
  accessToken: string;
  user: {
    id: string;
    name: string;
    email: string;
  };
};

@Injectable()
export class AuthService {
  private readonly usersByEmail = new Map<string, AuthUser>();

  constructor(private readonly jwtService: JwtService) {}

  async register(registerAuthDto: RegisterAuthDto): Promise<AuthResponse> {
    const normalizedEmail = registerAuthDto.email.toLowerCase().trim();
    const existingUser = this.usersByEmail.get(normalizedEmail);

    if (existingUser) {
      throw new ConflictException('Email is already registered');
    }

    const passwordHash = await bcrypt.hash(registerAuthDto.password, 10);

    const user: AuthUser = {
      id: randomUUID(),
      name: registerAuthDto.name.trim(),
      email: normalizedEmail,
      passwordHash,
    };

    this.usersByEmail.set(normalizedEmail, user);

    return this.buildAuthResponse(user);
  }

  async login(loginAuthDto: LoginAuthDto): Promise<AuthResponse> {
    const normalizedEmail = loginAuthDto.email.toLowerCase().trim();
    const user = this.usersByEmail.get(normalizedEmail);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(
      loginAuthDto.password,
      user.passwordHash,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    return this.buildAuthResponse(user);
  }

  private async buildAuthResponse(user: AuthUser): Promise<AuthResponse> {
    const accessToken = await this.jwtService.signAsync({
      sub: user.id,
      email: user.email,
      name: user.name,
    });

    return {
      accessToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    };
  }
}
