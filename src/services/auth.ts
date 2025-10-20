import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { JWTPayload } from '../types';

export class AuthService {
    private jwtSecret: string;
    private saltRounds: number;

    constructor() {
        this.jwtSecret = process.env.JWT_SECRET!;
        this.saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12');
    }

    async hashPassword(password: string): Promise<string> {
        return bcrypt.hash(password, this.saltRounds);
    }

    async verifyPassword(password: string, hash: string): Promise<boolean> {
        return bcrypt.compare(password, hash);
    }

    generateToken(userId: string): string {
        const payload: JWTPayload = {
            sub: userId,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (15 * 60)
        };

        return jwt.sign(payload, this.jwtSecret, { algorithm: 'HS256' });
    }

    verifyToken(token: string): JWTPayload | null {
        try {
            return jwt.verify(token, this.jwtSecret, { algorithms: ['HS256'] }) as JWTPayload;
        } catch {
            return null;
        }
    }

    isAdmin(userId: string): boolean {
        const adminIds = process.env.ADMIN_USER_IDS?.split(',') || [];
        return adminIds.includes(userId);
    }
}
