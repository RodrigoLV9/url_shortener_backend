import { IsEmail, IsString, MaxLength, MinLength } from 'class-validator';

export class RegisterAuthDto {
  @IsString()
  @MinLength(2)
  @MaxLength(80)
  name!: string;

  @IsEmail()
  email!: string;

  @IsString()
  @MinLength(8)
  @MaxLength(128)
  password!: string;
}
