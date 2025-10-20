import crypto from 'crypto';

export class CryptoService {
    private encKey: Buffer;
    private indexKey: Buffer;
    private signingKey: Buffer;

    constructor() {
        this.encKey = Buffer.from(process.env.ENC_KEY!, 'base64');
        this.indexKey = Buffer.from(process.env.INDEX_KEY!, 'base64');
        this.signingKey = Buffer.from(process.env.SIGNING_KEY!, 'base64');
    }

    encrypt(plaintext: string): string {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', this.encKey, iv);

        let encrypted = cipher.update(plaintext, 'utf8', 'base64');
        encrypted += cipher.final('base64');

        return `${iv.toString('base64')}:${encrypted}`;
    }

    decrypt(encryptedData: string): string {
        if (!encryptedData) return '';

        const [ivB64, ciphertext] = encryptedData.split(':');
        const iv = Buffer.from(ivB64, 'base64');

        const decipher = crypto.createDecipheriv('aes-256-cbc', this.encKey, iv);

        let decrypted = decipher.update(ciphertext, 'base64', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    }

    createEmailIndex(email: string): string {
        const normalized = email.trim().toLowerCase();
        return crypto.createHmac('sha256', this.indexKey).update(normalized).digest('hex');
    }

    createProofHash(data: any): string {
        const canonical = this.canonicalize(data);
        const entryHash = crypto.createHash('sha256').update(canonical).digest('hex');
        return crypto.createHmac('sha256', this.signingKey).update(entryHash).digest('hex');
    }

    private canonicalize(obj: any): string {
        const sorted = this.sortKeys(obj);
        return JSON.stringify(sorted);
    }

    private sortKeys(obj: any): any {
        if (obj === null || typeof obj !== 'object') return obj;
        if (Array.isArray(obj)) return obj.map(item => this.sortKeys(item));

        const sorted: any = {};
        Object.keys(obj).sort().forEach(key => {
            sorted[key] = this.sortKeys(obj[key]);
        });
        return sorted;
    }

    simulateKeyDestruction(): void {
        this.encKey = Buffer.alloc(32);
        this.indexKey = Buffer.alloc(32);
    }
}
