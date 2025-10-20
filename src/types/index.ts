export interface User {
    id: string;
    name_enc: string | null;
    email_enc: string | null;
    phone_enc: string | null;
    email_index: string | null;
    password_hash: string | null;
    is_deleted: boolean;
    created_at: string;
    deleted_at: string | null;
    deletion_method: 'overwrite' | 'crypto-shred' | null;
}

export interface AuditLog {
    id: string;
    user_id: string;
    action: 'CREATE' | 'DELETE_REQUEST' | 'DATA_PURGED' | 'KEY_DESTROYED' | 'BACKUP_SCRUBBED';
    deletion_method?: 'overwrite' | 'crypto-shred';
    affected_fields?: string[];
    performed_by: 'user' | 'system' | 'admin';
    timestamp: string;
    notes?: string;
    proof_hash: string;
    backup_scrub_status?: 'pending' | 'done';
}

export interface SignupRequest {
    name: string;
    email: string;
    phone: string;
    password: string;
}

export interface LoginRequest {
    email: string;
    password: string;
}

export interface SignupResponse {
    ok: boolean;
    userId: string;
}

export interface LoginResponse {
    ok: boolean;
}

export interface ProfileResponse {
    id: string;
    name: string;
    email: string;
    phone: string;
    created_at: string;
}

export interface DeleteResponse {
    ok: boolean;
    auditId: string;
    proof_hash: string;
}

export interface AuditResponse {
    logs: AuditLog[];
}

export interface HealthResponse {
    status: string;
    timestamp: string;
}

export interface JWTPayload {
    sub: string;
    iat: number;
    exp: number;
}

declare global {
    namespace Express {
        interface Request {
            userId?: string;
        }
    }
}
