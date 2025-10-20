import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { v4 as uuidv4 } from 'uuid';
import { DatabaseService } from './services/database';
import { CryptoService } from './services/crypto';
import { AuthService } from './services/auth';
import { Logger } from './services/logger';
import {
    SignupRequest,
    LoginRequest,
    SignupResponse,
    LoginResponse,
    ProfileResponse,
    DeleteResponse,
    AuditResponse,
    HealthResponse,
    User,
    AuditLog
} from './types';

export class Server {
    private app: express.Application;
    private db: DatabaseService;
    private crypto: CryptoService;
    private auth: AuthService;

    constructor() {
        this.app = express();
        this.db = new DatabaseService();
        this.crypto = new CryptoService();
        this.auth = new AuthService();

        this.setupMiddleware();
        this.setupRoutes();
    }

    private setupMiddleware(): void {
        this.app.use(cors({
            origin: process.env.FRONTEND_URL || 'http://localhost:3000',
            credentials: true
        }));
        this.app.use(express.json());
        this.app.use(cookieParser());
        this.app.use(express.static('public'));

        this.app.use((req, res, next) => {
            res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
            res.set('Pragma', 'no-cache');
            res.set('Expires', '0');
            next();
        });
    }

    private setupRoutes(): void {
        this.app.post('/signup', this.handleSignup.bind(this));
        this.app.post('/login', this.handleLogin.bind(this));
        this.app.get('/me', this.authenticate, this.handleGetProfile.bind(this));
        this.app.post('/me/delete', this.authenticate, this.handleDeleteProfile.bind(this));
        this.app.get('/audit/:userId', this.authenticate, this.handleGetAudit.bind(this));
        this.app.post('/simulate/crypto-shred', this.authenticate, this.handleCryptoShred.bind(this));
        this.app.get('/debug/db', this.authenticate, this.handleDebugDb.bind(this));
        this.app.get('/debug/audit', this.authenticate, this.handleDebugAudit.bind(this));
        this.app.get('/health', this.handleHealth.bind(this));
    }

    private authenticate = (req: express.Request, res: express.Response, next: express.NextFunction): void => {
        const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');

        if (!token) {
            res.status(401).json({ error: 'No token provided' });
            return;
        }

        const payload = this.auth.verifyToken(token);
        if (!payload) {
            res.status(401).json({ error: 'Invalid token' });
            return;
        }

        req.userId = payload.sub;
        next();
    };

    private async handleSignup(req: express.Request, res: express.Response): Promise<void> {
        try {
            const { name, email, phone, password }: SignupRequest = req.body;

            const emailIndex = this.crypto.createEmailIndex(email);
            const existingUser = await this.db.findUserByEmailIndex(emailIndex);

            if (existingUser) {
                res.status(400).json({ error: 'User already exists' });
                return;
            }

            const userId = uuidv4();
            const passwordHash = await this.auth.hashPassword(password);

            const user: User = {
                id: userId,
                name_enc: this.crypto.encrypt(name),
                email_enc: this.crypto.encrypt(email),
                phone_enc: this.crypto.encrypt(phone),
                email_index: emailIndex,
                password_hash: passwordHash,
                is_deleted: false,
                created_at: new Date().toISOString(),
                deleted_at: null,
                deletion_method: null
            };

            await this.db.createUser(user);

            const auditLog: AuditLog = {
                id: uuidv4(),
                user_id: userId,
                action: 'CREATE',
                performed_by: 'user',
                timestamp: new Date().toISOString(),
                notes: 'User account created',
                proof_hash: this.crypto.createProofHash({
                    user_id: userId,
                    action: 'CREATE',
                    timestamp: new Date().toISOString()
                })
            };

            await this.db.addAuditLog(auditLog);

            Logger.info('User created', { userId });

            const response: SignupResponse = { ok: true, userId };
            res.json(response);
        } catch (error) {
            Logger.error('Signup failed', { error: error instanceof Error ? error.message : 'Unknown error' });
            res.status(500).json({ error: 'Signup failed' });
        }
    }

    private async handleLogin(req: express.Request, res: express.Response): Promise<void> {
        try {
            const { email, password }: LoginRequest = req.body;

            const emailIndex = this.crypto.createEmailIndex(email);
            const user = await this.db.findUserByEmailIndex(emailIndex);

            if (!user || !user.password_hash || !await this.auth.verifyPassword(password, user.password_hash)) {
                res.status(401).json({ error: 'Invalid credentials' });
                return;
            }

            const token = this.auth.generateToken(user.id);

            res.cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax',
                maxAge: 15 * 60 * 1000
            });

            Logger.info('User logged in', { userId: user.id });

            const response: LoginResponse = { ok: true };
            res.json(response);
        } catch (error) {
            Logger.error('Login failed', { error: error instanceof Error ? error.message : 'Unknown error' });
            res.status(500).json({ error: 'Login failed' });
        }
    }

    private async handleGetProfile(req: express.Request, res: express.Response): Promise<void> {
        try {
            const user = await this.db.findUserById(req.userId!);

            if (!user || user.is_deleted) {
                res.status(404).json({ error: 'User not found' });
                return;
            }

            const response: ProfileResponse = {
                id: user.id,
                name: this.crypto.decrypt(user.name_enc!),
                email: this.crypto.decrypt(user.email_enc!),
                phone: this.crypto.decrypt(user.phone_enc!),
                created_at: user.created_at
            };

            res.json(response);
        } catch (error) {
            Logger.error('Get profile failed', { error: error instanceof Error ? error.message : 'Unknown error' });
            res.status(500).json({ error: 'Get profile failed' });
        }
    }

    private async handleDeleteProfile(req: express.Request, res: express.Response): Promise<void> {
        try {
            const user = await this.db.findUserById(req.userId!);

            if (!user || user.is_deleted) {
                res.status(404).json({ error: 'User not found' });
                return;
            }

            const auditId = uuidv4();

            const deleteRequestLog: AuditLog = {
                id: uuidv4(),
                user_id: user.id,
                action: 'DELETE_REQUEST',
                performed_by: 'user',
                timestamp: new Date().toISOString(),
                notes: 'User requested data deletion',
                proof_hash: this.crypto.createProofHash({
                    user_id: user.id,
                    action: 'DELETE_REQUEST',
                    timestamp: new Date().toISOString()
                })
            };

            await this.db.addAuditLog(deleteRequestLog);

            await this.db.updateUser(user.id, {
                name_enc: null,
                email_enc: null,
                phone_enc: null,
                email_index: null,
                password_hash: null,
                is_deleted: true,
                deleted_at: new Date().toISOString(),
                deletion_method: 'overwrite'
            });

            await this.db.createBackup();
            await this.db.scrubBackup();

            const dataPurgedLog: AuditLog = {
                id: auditId,
                user_id: user.id,
                action: 'DATA_PURGED',
                deletion_method: 'overwrite',
                affected_fields: ['name', 'email', 'phone', 'password_hash'],
                performed_by: 'system',
                timestamp: new Date().toISOString(),
                notes: 'PII data and password hash purged, backups scrubbed',
                proof_hash: this.crypto.createProofHash({
                    user_id: user.id,
                    action: 'DATA_PURGED',
                    deletion_method: 'overwrite',
                    affected_fields: ['name', 'email', 'phone', 'password_hash'],
                    timestamp: new Date().toISOString()
                }),
                backup_scrub_status: 'done'
            };

            await this.db.addAuditLog(dataPurgedLog);

            Logger.info('User data deleted', { userId: user.id });

            const response: DeleteResponse = {
                ok: true,
                auditId,
                proof_hash: dataPurgedLog.proof_hash
            };
            res.json(response);
        } catch (error) {
            Logger.error('Delete profile failed', { error: error instanceof Error ? error.message : 'Unknown error' });
            res.status(500).json({ error: 'Delete profile failed' });
        }
    }

    private async handleGetAudit(req: express.Request, res: express.Response): Promise<void> {
        try {
            const { userId } = req.params;
            const currentUserId = req.userId!;

            if (!this.auth.isAdmin(currentUserId) && currentUserId !== userId) {
                res.status(403).json({ error: 'Access denied' });
                return;
            }

            const logs = await this.db.getAuditLogs(userId);

            const response: AuditResponse = { logs };
            res.json(response);
        } catch (error) {
            Logger.error('Get audit failed', { error: error instanceof Error ? error.message : 'Unknown error' });
            res.status(500).json({ error: 'Get audit failed' });
        }
    }

    private async handleCryptoShred(req: express.Request, res: express.Response): Promise<void> {
        try {
            if (!this.auth.isAdmin(req.userId!)) {
                res.status(403).json({ error: 'Admin access required' });
                return;
            }

            this.crypto.simulateKeyDestruction();

            const keyDestroyedLog: AuditLog = {
                id: uuidv4(),
                user_id: 'system',
                action: 'KEY_DESTROYED',
                performed_by: 'admin',
                timestamp: new Date().toISOString(),
                notes: 'Encryption keys destroyed - crypto-shred simulation',
                proof_hash: this.crypto.createProofHash({
                    action: 'KEY_DESTROYED',
                    timestamp: new Date().toISOString()
                })
            };

            await this.db.addAuditLog(keyDestroyedLog);

            Logger.info('Crypto-shred simulation completed');

            res.json({ ok: true, message: 'Keys destroyed' });
        } catch (error) {
            Logger.error('Crypto-shred failed', { error: error instanceof Error ? error.message : 'Unknown error' });
            res.status(500).json({ error: 'Crypto-shred failed' });
        }
    }

    private async handleDebugDb(req: express.Request, res: express.Response): Promise<void> {
        try {
            if (!this.auth.isAdmin(req.userId!)) {
                res.status(403).json({ error: 'Admin access required' });
                return;
            }

            const users = this.db.users.map((user: User) => ({
                ...user,
                name_enc: user.name_enc ? '[ENCRYPTED]' : null,
                email_enc: user.email_enc ? '[ENCRYPTED]' : null,
                phone_enc: user.phone_enc ? '[ENCRYPTED]' : null,
                password_hash: '[HASHED]'
            }));

            res.json({ users });
        } catch (error) {
            Logger.error('Debug DB failed', { error: error instanceof Error ? error.message : 'Unknown error' });
            res.status(500).json({ error: 'Debug DB failed' });
        }
    }

    private async handleDebugAudit(req: express.Request, res: express.Response): Promise<void> {
        try {
            if (!this.auth.isAdmin(req.userId!)) {
                res.status(403).json({ error: 'Admin access required' });
                return;
            }

            const logs = await this.db.getAllAuditLogs();
            res.json({ audit_logs: logs });
        } catch (error) {
            Logger.error('Debug audit failed', { error: error instanceof Error ? error.message : 'Unknown error' });
            res.status(500).json({ error: 'Debug audit failed' });
        }
    }

    private async handleHealth(req: express.Request, res: express.Response): Promise<void> {
        const response: HealthResponse = {
            status: 'healthy',
            timestamp: new Date().toISOString()
        };
        res.json(response);
    }

    async start(port: number = 3000): Promise<void> {
        await this.db.initialize();
        this.app.listen(port, () => {
            Logger.info(`Server running on port ${port}`);
        });
    }
}
