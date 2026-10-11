import { NextRequest, NextResponse } from 'next/server';
import { commitPendingTransfer } from '@/lib/firewall/confirmation_store';
import { TransactionConfirmationRequest, TransactionConfirmationResponse } from '@/lib/firewall/types';

export async function POST(req: NextRequest) {
  // This endpoint is intentionally a synthetic demo. An unauthenticated demo
  // ledger must never be mistaken for a real banking integration.
  if (process.env.NODE_ENV === 'production' && process.env.BANKISM_DEMO_MODE !== 'true') {
    return NextResponse.json({
      success: false,
      execution_status: 'REJECTED',
      message: 'Demo ledger execution is disabled. Configure a real authentication and durable-ledger adapter before enabling production execution.',
    }, { status: 503 });
  }

  try {
    const body = (await req.json()) as Partial<TransactionConfirmationRequest>;
    if (!body || typeof body.request_id !== 'string' || typeof body.confirmation_token !== 'string' || typeof body.idempotency_key !== 'string') {
      return NextResponse.json({ success: false, execution_status: 'REJECTED', message: 'Missing request ID, confirmation token, or idempotency key.' }, { status: 400 });
    }

    const result = commitPendingTransfer({
      requestId: body.request_id,
      confirmationToken: body.confirmation_token,
      idempotencyKey: body.idempotency_key,
      confirmedAmount: body.confirmed_amount === undefined ? undefined : Number(body.confirmed_amount),
      confirmedRecipient: body.confirmed_recipient,
    });
    if (!result.ok) {
      return NextResponse.json({ success: false, execution_status: 'REJECTED', message: result.message }, { status: result.status });
    }

    const tx = result.record;
    const response: TransactionConfirmationResponse = {
      success: true,
      transaction_id: tx.transactionId,
      execution_status: 'EXECUTED',
      delta_amount: -tx.amount,
      previous_balance: tx.previousBalance,
      new_balance: tx.newBalance,
      message: result.replayed
        ? 'Idempotent replay: this exact transaction was already committed; no second debit occurred.'
        : `Simulated transfer of ${tx.amount.toFixed(2)} ${tx.currency} to ${tx.recipient} committed. No real funds moved.`,
      executed_at: tx.executedAt,
    };
    return NextResponse.json(response, { status: 200 });
  } catch (error) {
    console.error('Ledger confirmation error:', error);
    return NextResponse.json({ success: false, execution_status: 'REJECTED', message: 'Ledger confirmation failed closed.' }, { status: 500 });
  }
}
