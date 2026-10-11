import crypto from 'crypto';

/**
 * Demo-only confirmation store. State is process-local, so this adapter is NOT
 * suitable for multi-instance/serverless production use. Production requests
 * fail closed unless BANKISM_DEMO_MODE=true. Replace with a durable database
 * transaction + unique idempotency constraint before any real-money use.
 */
export interface PendingTransfer {
  requestId: string;
  userId: string;
  sourceAccountId: string;
  amount: number;
  recipient: string;
  currency: string;
  expiresAt: number;
  tokenId: string;
  idempotencyKey: string;
  used: boolean;
}

export interface CommittedTransfer {
  idempotencyKey: string;
  requestId: string;
  tokenId: string;
  transactionId: string;
  amount: number;
  recipient: string;
  currency: string;
  previousBalance: number;
  newBalance: number;
  executedAt: string;
}

interface StoreState {
  pending: Map<string, PendingTransfer>;
  committedByKey: Map<string, CommittedTransfer>;
  balance: number;
}

const globalStore = globalThis as typeof globalThis & { __bankismStore?: StoreState };
const store = globalStore.__bankismStore ??= {
  pending: new Map<string, PendingTransfer>(),
  committedByKey: new Map<string, CommittedTransfer>(),
  balance: 12450,
};

const TOKEN_TTL_MS = 5 * 60 * 1000;
const DEMO_USER_ID = 'demo-user';
const DEMO_ACCOUNT_ID = 'ACC_DEMO_0884';

export function getConfirmationSecret(): string {
  const secret = process.env.BANKISM_CONFIRMATION_SECRET;
  if (secret && secret.length >= 32) return secret;
  if (process.env.NODE_ENV !== 'production') {
    return 'local-development-only-secret-change-before-deploy-2026';
  }
  throw new Error('BANKISM_CONFIRMATION_SECRET must be configured (minimum 32 characters).');
}

function signToken(tokenId: string, pending: Omit<PendingTransfer, 'tokenId' | 'used'>): string {
  const payload = [
    tokenId, pending.requestId, pending.userId, pending.sourceAccountId,
    pending.recipient, pending.amount.toFixed(2), pending.currency,
    String(pending.expiresAt), pending.idempotencyKey,
  ].join('|');
  return crypto.createHmac('sha256', getConfirmationSecret()).update(payload).digest('hex');
}

export function getDemoBalance(): number {
  return store.balance;
}

/**
 * Test-only fixture hook for the benchmark. It deliberately cannot be enabled
 * in production. Tests must seed trusted server-side demo state rather than
 * passing a caller-controlled balance in account_context.
 */
export function setDemoBalanceForTests(balance: number): void {
  if (
    process.env.BANKISM_ALLOW_TEST_FIXTURES !== 'true' ||
    process.env.NODE_ENV === 'production'
  ) {
    throw new Error('Demo balance test fixtures are disabled.');
  }
  if (!Number.isFinite(balance) || balance < 0) {
    throw new Error('Test fixture balance must be a finite non-negative number.');
  }
  store.balance = Math.round(balance * 100) / 100;
}

export function createPendingTransfer(input: {
  requestId: string;
  amount: number;
  recipient: string;
  currency: string;
}): { confirmationToken: string; idempotencyKey: string } {
  if (!Number.isFinite(input.amount) || input.amount <= 0 || !input.recipient.trim()) {
    throw new Error('Invalid transfer parameters.');
  }
  const tokenId = crypto.randomBytes(24).toString('hex');
  const idempotencyKey = `idemp_${crypto.randomBytes(24).toString('hex')}`;
  const pending: PendingTransfer = {
    ...input,
    userId: DEMO_USER_ID,
    sourceAccountId: DEMO_ACCOUNT_ID,
    expiresAt: Date.now() + TOKEN_TTL_MS,
    tokenId,
    idempotencyKey,
    used: false,
  };
  store.pending.set(input.requestId, pending);
  return { confirmationToken: `cft_${tokenId}.${signToken(tokenId, pending)}`, idempotencyKey };
}

export type CommitResult =
  | { ok: true; replayed: boolean; record: CommittedTransfer }
  | { ok: false; status: number; message: string };

export function commitPendingTransfer(input: {
  requestId: string;
  confirmationToken: string;
  idempotencyKey: string;
  confirmedAmount?: number;
  confirmedRecipient?: string;
}): CommitResult {
  const existing = store.committedByKey.get(input.idempotencyKey);
  if (existing) {
    const tokenId = input.confirmationToken.match(/^cft_([a-f0-9]{48})\./)?.[1];
    if (existing.requestId === input.requestId && tokenId === existing.tokenId) {
      return { ok: true, replayed: true, record: existing };
    }
    return { ok: false, status: 409, message: 'Idempotency key already belongs to a different transaction.' };
  }

  const pending = store.pending.get(input.requestId);
  if (!pending) return { ok: false, status: 403, message: 'Unknown or expired confirmation request.' };

  const tokenMatch = input.confirmationToken.match(/^cft_([a-f0-9]{48})\.([a-f0-9]{64})$/);
  if (!tokenMatch || tokenMatch[1] !== pending.tokenId) {
    return { ok: false, status: 403, message: 'Invalid confirmation token.' };
  }
  const expectedSignature = signToken(pending.tokenId, pending);
  const suppliedSignature = Buffer.from(tokenMatch[2], 'hex');
  const expectedBuffer = Buffer.from(expectedSignature, 'hex');
  if (suppliedSignature.length !== expectedBuffer.length || !crypto.timingSafeEqual(suppliedSignature, expectedBuffer)) {
    return { ok: false, status: 403, message: 'Confirmation token signature verification failed.' };
  }
  if (input.idempotencyKey !== pending.idempotencyKey) {
    return { ok: false, status: 403, message: 'Idempotency key does not match the pending transaction.' };
  }
  if (pending.expiresAt < Date.now()) {
    store.pending.delete(input.requestId);
    return { ok: false, status: 410, message: 'Confirmation token expired. Inspect the request again.' };
  }
  if (pending.used) return { ok: false, status: 409, message: 'Confirmation token has already been used.' };
  if (input.confirmedAmount !== undefined && Number(input.confirmedAmount) !== pending.amount) {
    return { ok: false, status: 409, message: 'Confirmed amount differs from the server-approved amount.' };
  }
  if (input.confirmedRecipient !== undefined && input.confirmedRecipient !== pending.recipient) {
    return { ok: false, status: 409, message: 'Confirmed recipient differs from the server-approved recipient.' };
  }
  if (pending.amount > store.balance) return { ok: false, status: 400, message: 'Insufficient funds in the demo ledger.' };

  // All validation and state mutation are synchronous in this demo adapter.
  // A durable adapter must perform these operations in one DB transaction.
  const previousBalance = store.balance;
  const newBalance = Math.round((previousBalance - pending.amount) * 100) / 100;
  const record: CommittedTransfer = {
    idempotencyKey: pending.idempotencyKey,
    requestId: pending.requestId,
    tokenId: pending.tokenId,
    transactionId: `tx_demo_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`,
    amount: pending.amount,
    recipient: pending.recipient,
    currency: pending.currency,
    previousBalance,
    newBalance,
    executedAt: new Date().toISOString(),
  };
  store.balance = newBalance;
  pending.used = true;
  store.committedByKey.set(pending.idempotencyKey, record);
  store.pending.delete(input.requestId);
  return { ok: true, replayed: false, record };
}
