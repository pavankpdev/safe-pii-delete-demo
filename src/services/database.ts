import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import { User, AuditLog } from '../types';

interface Database {
    users: User[];
    audit_logs: AuditLog[];
}

export class DatabaseService {
    private db: Low<Database>;
    private auditDb: Low<Database>;

    constructor() {
        const usersAdapter = new JSONFile<Database>('db.json');
        const auditAdapter = new JSONFile<Database>('audit.json');

        this.db = new Low(usersAdapter, { users: [], audit_logs: [] });
        this.auditDb = new Low(auditAdapter, { users: [], audit_logs: [] });
    }

    async initialize(): Promise<void> {
        await this.db.read();
        await this.auditDb.read();

        if (this.db.data.users.length === 0) {
            await this.createAdminUser();
        }
    }

    get users() {
        return this.db.data.users;
    }

    private async createAdminUser(): Promise<void> {
        const crypto = new (await import('./crypto')).CryptoService();
        const adminId = '00000000-0000-0000-0000-000000000001';
        const adminEmail = 'admin@example.com';

        const adminUser: User = {
            id: adminId,
            name_enc: crypto.encrypt('Admin User'),
            email_enc: crypto.encrypt(adminEmail),
            phone_enc: crypto.encrypt('+1234567890'),
            email_index: crypto.createEmailIndex(adminEmail),
            password_hash: '$2b$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
            is_deleted: false,
            created_at: new Date().toISOString(),
            deleted_at: null,
            deletion_method: null
        };

        this.db.data.users.push(adminUser);
        await this.db.write();
    }

    async createUser(user: User): Promise<void> {
        this.db.data.users.push(user);
        await this.db.write();
    }

    async findUserByEmailIndex(emailIndex: string): Promise<User | undefined> {
        return this.db.data.users.find(u => u.email_index === emailIndex && !u.is_deleted);
    }

    async findUserById(id: string): Promise<User | undefined> {
        return this.db.data.users.find(u => u.id === id);
    }

    async updateUser(id: string, updates: Partial<User>): Promise<void> {
        const userIndex = this.db.data.users.findIndex(u => u.id === id);
        if (userIndex !== -1) {
            this.db.data.users[userIndex] = { ...this.db.data.users[userIndex], ...updates };
            await this.db.write();
        }
    }

    async addAuditLog(log: AuditLog): Promise<void> {
        this.auditDb.data.audit_logs.push(log);
        await this.auditDb.write();
    }

    async getAuditLogs(userId: string): Promise<AuditLog[]> {
        return this.auditDb.data.audit_logs.filter(log => log.user_id === userId);
    }

    async getAllAuditLogs(): Promise<AuditLog[]> {
        return this.auditDb.data.audit_logs;
    }

    async createBackup(): Promise<void> {
        const fs = await import('fs/promises');
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupPath = `backups/snapshot-${timestamp}.json`;

        await fs.mkdir('backups', { recursive: true });
        await fs.writeFile(backupPath, JSON.stringify(this.db.data, null, 2));
    }

    async scrubBackup(): Promise<void> {
        const fs = await import('fs/promises');
        const files = await fs.readdir('backups');

        for (const file of files) {
            if (file.startsWith('snapshot-')) {
                const content = await fs.readFile(`backups/${file}`, 'utf8');
                const data = JSON.parse(content);

                data.users.forEach((user: User) => {
                    if (user.is_deleted) {
                        user.name_enc = null;
                        user.email_enc = null;
                        user.phone_enc = null;
                        user.email_index = null;
                        user.password_hash = null;
                    }
                });

                await fs.writeFile(`backups/${file}`, JSON.stringify(data, null, 2));
            }
        }
    }
}
