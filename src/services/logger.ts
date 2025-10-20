export class Logger {
    private static readonly PII_PATTERNS = [
        /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
        /^\+?[\d\s\-\(\)]{10,}$/,
        /^[A-Za-z\s]{2,50}$/
    ];

    private static readonly PII_KEYS = ['email', 'phone', 'name', 'password'];

    static info(message: string, data?: any): void {
        this.log('INFO', message, data);
    }

    static error(message: string, data?: any): void {
        this.log('ERROR', message, data);
    }

    static warn(message: string, data?: any): void {
        this.log('WARN', message, data);
    }

    private static log(level: string, message: string, data?: any): void {
        if (data) {
            this.validateNoPII(data);
        }

        const timestamp = new Date().toISOString();
        console.log(`[${timestamp}] ${level}: ${message}`, data ? this.sanitizeData(data) : '');
    }

    private static validateNoPII(data: any): void {
        if (typeof data === 'string') {
            if (this.PII_PATTERNS.some(pattern => pattern.test(data))) {
                throw new Error('PII detected in log data - email, phone, or name pattern found');
            }
        } else if (typeof data === 'object' && data !== null) {
            for (const [key, value] of Object.entries(data)) {
                if (this.PII_KEYS.includes(key.toLowerCase()) || key.endsWith('_enc')) {
                    throw new Error(`PII detected in log data - sensitive key '${key}' found`);
                }
                if (typeof value === 'string' && this.PII_PATTERNS.some(pattern => pattern.test(value))) {
                    throw new Error('PII detected in log data - email, phone, or name pattern found');
                }
                if (typeof value === 'object') {
                    this.validateNoPII(value);
                }
            }
        }
    }

    private static sanitizeData(data: any): any {
        if (typeof data === 'string') {
            return '[REDACTED]';
        } else if (typeof data === 'object' && data !== null) {
            const sanitized: any = {};
            for (const [key, value] of Object.entries(data)) {
                if (this.PII_KEYS.includes(key.toLowerCase()) || key.endsWith('_enc')) {
                    sanitized[key] = '[REDACTED]';
                } else if (typeof value === 'object') {
                    sanitized[key] = this.sanitizeData(value);
                } else {
                    sanitized[key] = value;
                }
            }
            return sanitized;
        }
        return data;
    }
}
