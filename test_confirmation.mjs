import assert from 'node:assert/strict';
import { createPendingTransfer, commitPendingTransfer, getDemoBalance } from './src/lib/firewall/confirmation_store.ts';

function fixture(suffix) {
  const requestId = `test_confirm_${suffix}_${Date.now()}_${Math.random().toString(16).slice(2)}`;
  const pending = createPendingTransfer({ requestId, amount: 12.5, recipient: 'Alice Demo', currency: 'USD' });
  return { requestId, ...pending };
}

const startBalance = getDemoBalance();
const alteredAmount = fixture('amount');
const amountTamper = commitPendingTransfer({
  requestId: alteredAmount.requestId,
  confirmationToken: alteredAmount.confirmationToken,
  idempotencyKey: alteredAmount.idempotencyKey,
  confirmedAmount: 999,
  confirmedRecipient: 'Alice Demo',
});
assert.equal(amountTamper.ok, false, 'altered amount must be rejected');

const alteredRecipient = fixture('recipient');
const recipientTamper = commitPendingTransfer({
  requestId: alteredRecipient.requestId,
  confirmationToken: alteredRecipient.confirmationToken,
  idempotencyKey: alteredRecipient.idempotencyKey,
  confirmedAmount: 12.5,
  confirmedRecipient: 'Mallory',
});
assert.equal(recipientTamper.ok, false, 'recipient substitution must be rejected');

const tamperedToken = fixture('token');
const replacementLastChar = tamperedToken.confirmationToken.endsWith('0') ? '1' : '0';
const tokenTamper = commitPendingTransfer({
  requestId: tamperedToken.requestId,
  confirmationToken: `${tamperedToken.confirmationToken.slice(0, -1)}${replacementLastChar}`, 
  idempotencyKey: tamperedToken.idempotencyKey,
});
assert.equal(tokenTamper.ok, false, 'tampered token must be rejected');

const valid = fixture('valid');
const first = commitPendingTransfer({
  requestId: valid.requestId,
  confirmationToken: valid.confirmationToken,
  idempotencyKey: valid.idempotencyKey,
  confirmedAmount: 12.5,
  confirmedRecipient: 'Alice Demo',
});
assert.equal(first.ok, true, 'valid confirmation should commit in the synthetic ledger');
if (!first.ok) throw new Error(first.message);
assert.equal(first.replayed, false);
assert.equal(first.record.newBalance, Math.round((startBalance - 12.5) * 100) / 100);

const replay = commitPendingTransfer({
  requestId: valid.requestId,
  confirmationToken: valid.confirmationToken,
  idempotencyKey: valid.idempotencyKey,
  confirmedAmount: 12.5,
  confirmedRecipient: 'Alice Demo',
});
assert.equal(replay.ok, true, 'exact replay should return prior result');
if (!replay.ok) throw new Error(replay.message);
assert.equal(replay.replayed, true);
assert.equal(replay.record.transactionId, first.record.transactionId, 'replay must not create a second transaction');
assert.equal(getDemoBalance(), first.record.newBalance, 'replay must not debit a second time');

const wrongKey = commitPendingTransfer({
  requestId: valid.requestId,
  confirmationToken: valid.confirmationToken,
  idempotencyKey: 'idemp_wrong_key',
});
assert.equal(wrongKey.ok, false, 'wrong idempotency key must be rejected');

console.log('PASS confirmation security tests: amount tampering, recipient substitution, token tampering, idempotency replay, wrong key');
