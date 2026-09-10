// SPDX-License-Identifier: Apache-2.0

import * as http from "node:http";
import { URL } from "node:url";
import * as path from "node:path";
import { createPublicClient, http as viemHttp, type Address, getAddress, parseEther } from "viem";
import { foundry } from "viem/chains";
import { DealManager, DealStatus } from "../deal.js";
import {
  type TechnocoreRecord,
  tryDecodeTclkFrame,
  isTclkLine,
} from "../transport.js";
import { WalletSession } from "./session.js";
import {
  DealWalletApp,
  OrchestratorError,
  UnauthorizedActorError,
  DealStateMismatchError,
} from "./orchestrator.js";
import type { SessionRole, ArchivedDealSummary } from "./types.js";

// -----------------------------------------------------------------------------
// Safe Public Data Transfer Objects (DTOs)
// -----------------------------------------------------------------------------

export interface SafeDealDto {
  contractId: string;
  offerId: string;
  room: string;
  status: DealStatus;
  role: "payer" | "payee";
  payer: { did: string; evmAddress?: Address };
  payee: { did: string; evmAddress?: Address };
  amount: string;
  asset: string;
  lock: string;
  statement?: string; // Hashlock statement only; NEVER secret preimage
  claimByMs: number;
  refundAfterMs: number;
  expiresMs: number;
  createdAtMs: number;
  updatedAtMs: number;
  isTerminal: boolean;
}

export interface SafeSessionMetadataDto {
  did: string;
  evmAddress: Address;
  chainId: number;
  role: SessionRole;
  htlcAddress: Address;
  room: string;
}

export interface SafeBalanceDto {
  balance: string;
  formatted: string;
  chainId: number;
  evmAddress: Address;
}

export interface SafeDealsResponseDto {
  active: SafeDealDto[];
  completed: SafeDealDto[];
  counts: {
    active: number;
    completed: number;
    total: number;
  };
}

export interface SafeArchivesResponseDto {
  archives: ArchivedDealSummary[];
  count: number;
}

export interface HealthResponseDto {
  status: "ok";
  uptime: number;
  timestamp: number;
}

export interface SafeMessageDto {
  seq: number;
  ts: string;
  from: string;
  isSelf: boolean;
  text: string;
  isProtocol: boolean;
  frameType: string | null;
  contractOrOfferId: string | null;
}

export interface SafeMessagesResponseDto {
  messages: SafeMessageDto[];
  count: number;
}

export interface CreateOfferRequestDto {
  amountEth: string;
  claimBySec?: number;
  refundAfterSec?: number;
  expiresSec?: number;
  counterpartyDid?: string;
  role?: "payer" | "payee";
}

export interface DealActionResponseDto {
  ok: boolean;
  action: string;
  deal?: SafeDealDto;
}

/**
 * Projects a DealManager instance into an explicitly safe, public DTO.
 * Guarantees zero exposure of private keys, preimages, seeds, or RPC secrets.
 */
export function toSafeDealDto(deal: DealManager): SafeDealDto {
  const s = deal.state;
  return {
    contractId: deal.contractId || "",
    offerId: s.offer.id,
    room: deal.room,
    status: deal.status,
    role: s.offer.role,
    payer: {
      did: s.payer.did,
      evmAddress: s.payer.evmAddress,
    },
    payee: {
      did: s.payee.did,
      evmAddress: s.payee.evmAddress,
    },
    amount: s.offer.amount,
    asset: s.offer.asset,
    lock: s.offer.lock,
    statement: deal.terms?.statement ?? s.accept?.statement,
    claimByMs: s.offer.claimByMs,
    refundAfterMs: s.offer.refundAfterMs,
    expiresMs: s.offer.expiresMs,
    createdAtMs: s.createdAtMs,
    updatedAtMs: s.updatedAtMs,
    isTerminal: deal.isTerminal(),
  };
}

// -----------------------------------------------------------------------------
// Server Configuration
// -----------------------------------------------------------------------------

export interface DealWalletServerConfig {
  app: DealWalletApp;
  host?: string;
  port?: number;
  syncIntervalMs?: number;
}

// -----------------------------------------------------------------------------
// Security & Body Helpers
// -----------------------------------------------------------------------------

const MAX_BODY_BYTES = 65536; // 64 KB limit

export class HttpPayloadError extends Error {
  public statusCode: number;
  constructor(message: string, statusCode = 400) {
    super(message);
    this.name = "HttpPayloadError";
    this.statusCode = statusCode;
  }
}

export async function readJsonBody<T = unknown>(req: http.IncomingMessage): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let bytesReceived = 0;
    const chunks: Buffer[] = [];

    const contentLength = req.headers["content-length"];
    if (contentLength && parseInt(contentLength, 10) > MAX_BODY_BYTES) {
      reject(new HttpPayloadError(`Payload exceeds max body limit of ${MAX_BODY_BYTES} bytes`, 413));
      return;
    }

    req.on("data", (chunk: Buffer) => {
      bytesReceived += chunk.length;
      if (bytesReceived > MAX_BODY_BYTES) {
        req.destroy();
        reject(new HttpPayloadError(`Payload exceeds max body limit of ${MAX_BODY_BYTES} bytes`, 413));
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      if (chunks.length === 0) {
        resolve({} as T);
        return;
      }
      const raw = Buffer.concat(chunks).toString("utf-8").trim();
      if (!raw) {
        resolve({} as T);
        return;
      }
      try {
        const parsed = JSON.parse(raw);
        resolve(parsed as T);
      } catch {
        reject(new HttpPayloadError("Malformed JSON payload in request body", 400));
      }
    });

    req.on("error", (err) => {
      reject(new HttpPayloadError(`Error reading request body: ${err.message}`, 400));
    });
  });
}

export function sanitizeErrorMessage(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  return raw
    .replace(/https?:\/\/[^\s@]+@/gi, "http://[REDACTED]@")
    .replace(/0x[0-9a-fA-F]{64}/g, "0x[REDACTED]")
    .slice(0, 300);
}

// -----------------------------------------------------------------------------
// Embedded Dashboard HTML Template
// -----------------------------------------------------------------------------

export function renderDashboardHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Technocore Deal Wallet</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base: #080c14;
      --bg-surface: #0f172a;
      --bg-card: rgba(15, 23, 42, 0.75);
      --bg-card-hover: rgba(30, 41, 59, 0.85);
      --border-subtle: rgba(255, 255, 255, 0.08);
      --border-focus: rgba(0, 242, 254, 0.4);
      --accent-cyan: #00f2fe;
      --accent-blue: #4facfe;
      --accent-emerald: #10b981;
      --accent-amber: #f59e0b;
      --accent-purple: #8b5cf6;
      --accent-rose: #f43f5e;
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --font-sans: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background-color: var(--bg-base);
      color: var(--text-primary);
      font-family: var(--font-sans);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      line-height: 1.5;
      background-image:
        radial-gradient(circle at 10% 20%, rgba(0, 242, 254, 0.04) 0%, transparent 40%),
        radial-gradient(circle at 90% 80%, rgba(139, 92, 246, 0.04) 0%, transparent 40%);
    }

    header {
      border-bottom: 1px solid var(--border-subtle);
      background: rgba(15, 23, 42, 0.8);
      backdrop-filter: blur(12px);
      padding: 16px 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .logo-badge {
      background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
      width: 34px;
      height: 34px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      color: #080c14;
      font-size: 18px;
      box-shadow: 0 0 16px rgba(0, 242, 254, 0.35);
    }

    .brand h1 {
      font-size: 17px;
      font-weight: 700;
      letter-spacing: -0.02em;
    }

    .brand span {
      color: var(--accent-cyan);
    }

    .header-status {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 5px 12px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
      background: rgba(16, 185, 129, 0.1);
      color: var(--accent-emerald);
      border: 1px solid rgba(16, 185, 129, 0.2);
    }

    .pulse-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--accent-emerald);
      box-shadow: 0 0 8px var(--accent-emerald);
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(0.85); }
    }

    .container {
      max-width: 1600px;
      width: 100%;
      margin: 0 auto;
      padding: 24px;
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: 24px;
    }

    /* Split Dashboard: 50% Left (Room/Chat) and 50% Right (Deals/Lifecycle) */
    .dashboard-grid {
      display: grid;
      grid-template-columns: 480px 1fr;
      gap: 24px;
      align-items: start;
    }

    @media (max-width: 1100px) {
      .dashboard-grid {
        grid-template-columns: 1fr;
      }
    }

    .card {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 14px;
      padding: 20px;
      backdrop-filter: blur(16px);
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .card-title {
      font-size: 15px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-secondary);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .tag {
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 4px;
      font-weight: 600;
      font-family: var(--font-mono);
      text-transform: uppercase;
    }
    .tag-cyan { background: rgba(0, 242, 254, 0.1); color: var(--accent-cyan); border: 1px solid rgba(0, 242, 254, 0.25); }
    .tag-blue { background: rgba(79, 172, 254, 0.1); color: var(--accent-blue); border: 1px solid rgba(79, 172, 254, 0.25); }
    .tag-emerald { background: rgba(16, 185, 129, 0.1); color: var(--accent-emerald); border: 1px solid rgba(16, 185, 129, 0.25); }
    .tag-amber { background: rgba(245, 158, 11, 0.1); color: var(--accent-amber); border: 1px solid rgba(245, 158, 11, 0.25); }
    .tag-purple { background: rgba(139, 92, 246, 0.1); color: var(--accent-purple); border: 1px solid rgba(139, 92, 246, 0.25); }
    .tag-rose { background: rgba(244, 63, 94, 0.1); color: var(--accent-rose); border: 1px solid rgba(244, 63, 94, 0.25); }

    /* Identity & Stats Row */
    .stats-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
    }

    .stat-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      padding: 14px 18px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .stat-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      font-weight: 600;
    }

    .stat-value {
      font-family: var(--font-mono);
      font-size: 13px;
      font-weight: 600;
      color: var(--text-primary);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    /* Left: Room Chat & Stream */
    .room-pane {
      display: flex;
      flex-direction: column;
      height: 760px;
    }

    .messages-container {
      flex: 1;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 10px;
      padding: 12px;
      background: rgba(8, 12, 20, 0.6);
      border-radius: 10px;
      border: 1px solid var(--border-subtle);
    }

    .msg-item {
      display: flex;
      flex-direction: column;
      gap: 4px;
      padding: 8px 12px;
      border-radius: 8px;
      font-size: 13px;
      background: rgba(15, 23, 42, 0.6);
      border-left: 3px solid var(--accent-cyan);
    }
    .msg-item.self {
      border-left-color: var(--accent-purple);
      background: rgba(139, 92, 246, 0.07);
    }
    .msg-item.protocol {
      border-left-color: var(--accent-amber);
      background: rgba(245, 158, 11, 0.07);
    }

    .msg-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 11px;
      color: var(--text-muted);
    }

    .msg-author {
      font-family: var(--font-mono);
      font-weight: 600;
      color: var(--accent-cyan);
    }
    .msg-item.self .msg-author { color: var(--accent-purple); }
    .msg-item.protocol .msg-author { color: var(--accent-amber); }

    .msg-text {
      color: var(--text-primary);
      word-break: break-word;
      white-space: pre-wrap;
      font-family: var(--font-mono);
      font-size: 12px;
    }

    .chat-composer {
      display: flex;
      gap: 8px;
      margin-top: 12px;
    }

    .chat-input {
      flex: 1;
      background: rgba(15, 23, 42, 0.9);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 10px 14px;
      color: var(--text-primary);
      font-family: var(--font-sans);
      font-size: 13px;
    }
    .chat-input:focus {
      outline: none;
      border-color: var(--accent-cyan);
      box-shadow: 0 0 0 2px rgba(0, 242, 254, 0.2);
    }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      padding: 8px 16px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid transparent;
      transition: all 0.15s ease;
      font-family: var(--font-sans);
    }
    .btn-primary {
      background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
      color: #080c14;
      font-weight: 700;
    }
    .btn-primary:hover {
      box-shadow: 0 0 14px rgba(0, 242, 254, 0.4);
      transform: translateY(-1px);
    }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.06);
      color: var(--text-primary);
      border: 1px solid var(--border-subtle);
    }
    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.1);
    }
    .btn-action {
      font-size: 12px;
      padding: 6px 12px;
      border-radius: 6px;
    }
    .btn-emerald { background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald); border: 1px solid rgba(16, 185, 129, 0.3); }
    .btn-emerald:hover { background: rgba(16, 185, 129, 0.25); }
    .btn-amber { background: rgba(245, 158, 11, 0.15); color: var(--accent-amber); border: 1px solid rgba(245, 158, 11, 0.3); }
    .btn-amber:hover { background: rgba(245, 158, 11, 0.25); }
    .btn-purple { background: rgba(139, 92, 246, 0.15); color: var(--accent-purple); border: 1px solid rgba(139, 92, 246, 0.3); }
    .btn-purple:hover { background: rgba(139, 92, 246, 0.25); }
    .btn-rose { background: rgba(244, 63, 94, 0.15); color: var(--accent-rose); border: 1px solid rgba(244, 63, 94, 0.3); }
    .btn-rose:hover { background: rgba(244, 63, 94, 0.25); }

    /* Right: Deals List & Lifecycle */
    .deal-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 12px;
      transition: all 0.15s ease;
    }
    .deal-card:hover {
      border-color: rgba(255, 255, 255, 0.15);
    }

    .deal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .deal-title {
      font-family: var(--font-mono);
      font-size: 13px;
      font-weight: 700;
      color: var(--text-primary);
    }

    /* Lifecycle Step Progress */
    .timeline {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 4px;
      background: rgba(8, 12, 20, 0.7);
      padding: 8px 12px;
      border-radius: 8px;
      border: 1px solid var(--border-subtle);
      margin: 4px 0;
      overflow-x: auto;
    }

    .step-node {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      font-weight: 600;
      color: var(--text-muted);
      white-space: nowrap;
    }
    .step-node.completed {
      color: var(--accent-cyan);
    }
    .step-node.active {
      color: #080c14;
      background: var(--accent-cyan);
      padding: 2px 8px;
      border-radius: 4px;
      font-weight: 700;
      box-shadow: 0 0 10px rgba(0, 242, 254, 0.5);
    }
    .step-node.terminal {
      background: var(--accent-emerald);
      color: #080c14;
    }
    .step-divider {
      color: var(--border-subtle);
      font-size: 12px;
    }

    .deal-details-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 8px;
      font-size: 12px;
      background: rgba(0, 0, 0, 0.2);
      padding: 10px;
      border-radius: 6px;
    }
    .detail-item {
      display: flex;
      flex-direction: column;
    }
    .detail-k { color: var(--text-muted); font-size: 10px; text-transform: uppercase; }
    .detail-v { font-family: var(--font-mono); color: var(--text-secondary); word-break: break-all; }

    .deal-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 4px;
    }

    /* Modal / Form */
    .offer-form {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
      background: rgba(8, 12, 20, 0.8);
      padding: 16px;
      border-radius: 10px;
      border: 1px solid var(--border-focus);
      margin-bottom: 16px;
    }
    .form-group {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .form-group label {
      font-size: 11px;
      text-transform: uppercase;
      color: var(--text-muted);
      font-weight: 600;
    }
    .form-group input {
      background: rgba(15, 23, 42, 0.9);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 8px 10px;
      color: var(--text-primary);
      font-family: var(--font-mono);
      font-size: 12px;
    }
    .form-group input:focus {
      outline: none;
      border-color: var(--accent-cyan);
    }

    .empty-placeholder {
      text-align: center;
      padding: 32px;
      color: var(--text-muted);
      font-size: 13px;
    }

    #action-feedback {
      position: fixed;
      bottom: 24px;
      right: 24px;
      padding: 12px 18px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      z-index: 1000;
      display: none;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
    }
    #action-feedback.success { background: rgba(16, 185, 129, 0.9); color: #fff; display: block; }
    #action-feedback.error { background: rgba(244, 63, 94, 0.9); color: #fff; display: block; }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <div class="logo-badge">⚡</div>
      <div>
        <h1>Technocore <span>Deal Wallet</span></h1>
        <div class="subtitle" style="font-size: 11px; color: var(--text-muted);">tclk/1 EVM Settlement Rail</div>
      </div>
    </div>
    <div class="header-status">
      <div class="status-badge">
        <div class="pulse-dot" id="pulse-dot"></div>
        <span id="connection-status">Live Connected</span>
      </div>
    </div>
  </header>

  <div class="container">
    <!-- Top Identity & Stats Row -->
    <div class="stats-row">
      <div class="stat-card">
        <div class="stat-label">Session DID</div>
        <div class="stat-value" id="session-did">—</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Wallet Address</div>
        <div class="stat-value" id="session-address">—</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Balance</div>
        <div class="stat-value" id="session-balance">—</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Configured Role</div>
        <div class="stat-value" id="session-role">—</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Room / Chain</div>
        <div class="stat-value" id="session-room">—</div>
      </div>
    </div>

    <!-- Main Grid: Left Room / Right Deals -->
    <div class="dashboard-grid">
      <!-- Left: Technocore Room & Chat -->
      <div class="card room-pane">
        <div class="card-title">
          <span>Technocore Room Stream</span>
          <span class="tag tag-cyan" id="room-badge">room</span>
        </div>
        <div class="messages-container" id="messages-container">
          <div class="empty-placeholder">Connecting to room transcript...</div>
        </div>
        <form class="chat-composer" id="chat-form">
          <input type="text" id="chat-input" class="chat-input" placeholder="Type a message to the room..." autocomplete="off" maxlength="4096" />
          <button type="submit" class="btn btn-primary" id="btn-send-chat">Send</button>
        </form>
      </div>

      <!-- Right: Deals & Action Controls -->
      <div class="card">
        <div class="card-title">
          <span>EVM HTLC Deals</span>
          <button class="btn btn-secondary btn-action" id="toggle-offer-form">+ Create Offer</button>
        </div>

        <!-- Inline Create Offer Form (hidden by default) -->
        <form class="offer-form" id="offer-form" style="display: none;">
          <div class="form-group">
            <label>Amount (ETH)</label>
            <input type="text" id="offer-amount-eth" placeholder="0.01" value="0.01" required />
          </div>
          <div class="form-group">
            <label>Counterparty DID (Optional)</label>
            <input type="text" id="offer-counterparty-did" placeholder="did:key:z..." />
          </div>
          <div class="form-group">
            <label>Claim Deadline (Sec)</label>
            <input type="number" id="offer-claim-sec" value="600" required min="60" />
          </div>
          <div class="form-group">
            <label>Refund Deadline (Sec)</label>
            <input type="number" id="offer-refund-sec" value="1200" required min="120" />
          </div>
          <div class="form-group" style="grid-column: 1 / -1; display: flex; justify-content: flex-end; gap: 8px;">
            <button type="button" class="btn btn-secondary btn-action" id="cancel-offer-btn">Cancel</button>
            <button type="submit" class="btn btn-primary btn-action" id="submit-offer-btn">Publish Offer</button>
          </div>
        </form>

        <div id="deals-list" style="display: flex; flex-direction: column; gap: 14px;">
          <div class="empty-placeholder">No deals found in this session.</div>
        </div>
      </div>
    </div>
  </div>

  <div id="action-feedback"></div>

  <script>
    let myDid = '';
    let myRole = '';

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function shortenHex(str, len = 6) {
      if (!str || str.length <= len * 2 + 2) return str || '';
      return str.slice(0, len + 2) + '...' + str.slice(-len);
    }

    function showFeedback(msg, isError = false) {
      const el = document.getElementById('action-feedback');
      el.textContent = msg;
      el.className = isError ? 'error' : 'success';
      setTimeout(() => {
        el.className = '';
      }, 4000);
    }

    async function executeDealAction(id, action) {
      try {
        const res = await fetch('/api/deals/' + encodeURIComponent(id) + '/' + action, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({})
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.message || data.error || 'Action failed');
        }
        showFeedback('Action ' + action + ' succeeded!');
        await poll();
      } catch (err) {
        showFeedback(err.message, true);
      }
    }

    function renderTimeline(deal) {
      const steps = ['OFFER', 'ACCEPTED', 'LOCKED', 'VERIFIED', 'REVEALED', 'CLAIMED'];
      const st = deal.status;
      const isRefunded = (st === 'REFUNDED');
      const isCancelled = (st === 'CANCELLED');

      let currentIdx = steps.indexOf(st);
      if (currentIdx === -1 && (isRefunded || isCancelled)) {
        currentIdx = steps.length;
      }

      let html = '<div class="timeline">';
      steps.forEach((step, idx) => {
        const isCurrent = (st === step);
        const isPast = (idx < currentIdx);
        let cls = 'step-node';
        if (isCurrent) cls += ' active';
        else if (isPast) cls += ' completed';
        if (step === 'CLAIMED' && isCurrent) cls += ' terminal';

        html += '<div class="' + cls + '">' + step + '</div>';
        if (idx < steps.length - 1) {
          html += '<span class="step-divider">→</span>';
        }
      });

      if (isRefunded) {
        html += '<span class="step-divider">→</span><div class="step-node active terminal">REFUNDED</div>';
      } else if (isCancelled) {
        html += '<span class="step-divider">→</span><div class="step-node active" style="background:var(--accent-rose); color:#fff;">CANCELLED</div>';
      }

      html += '</div>';
      return html;
    }

    function renderDealCard(deal) {
      const id = deal.contractId || deal.offerId;
      const isPayer = (deal.payer && deal.payer.did === myDid);
      const isPayee = (deal.payee && deal.payee.did === myDid);
      const st = deal.status;

      let actions = [];
      // Role-aware actions
      if (st === 'OFFER') {
        if (!isPayer) actions.push({ name: 'Accept', action: 'accept', cls: 'btn-emerald' });
        if (isPayer) actions.push({ name: 'Cancel', action: 'cancel', cls: 'btn-rose' });
      } else if (st === 'ACCEPTED') {
        if (isPayer) actions.push({ name: 'Lock Funds', action: 'lock', cls: 'btn-cyan' });
        actions.push({ name: 'Cancel', action: 'cancel', cls: 'btn-rose' });
      } else if (st === 'LOCKED') {
        actions.push({ name: 'Verify', action: 'verify', cls: 'btn-blue' });
        if (isPayee) actions.push({ name: 'Reveal Secret', action: 'reveal', cls: 'btn-purple' });
        if (isPayer) actions.push({ name: 'Refund', action: 'refund', cls: 'btn-amber' });
      } else if (st === 'VERIFIED') {
        if (isPayee) actions.push({ name: 'Reveal Secret', action: 'reveal', cls: 'btn-purple' });
        if (isPayer) actions.push({ name: 'Refund', action: 'refund', cls: 'btn-amber' });
      } else if (st === 'REVEALED') {
        if (isPayee) actions.push({ name: 'Claim Funds', action: 'claim', cls: 'btn-emerald' });
        if (isPayer) actions.push({ name: 'Refund', action: 'refund', cls: 'btn-amber' });
      }

      const actionsHtml = actions.map((a) => '<button class="btn btn-action ' + a.cls + '" onclick="executeDealAction(\\'' + escapeHtml(id) + '\\', \\'' + a.action + '\\')">' + a.name + '</button>').join('');

      return \`
        <div class="deal-card">
          <div class="deal-header">
            <span class="deal-title">\${deal.contractId ? 'Contract: ' + escapeHtml(shortenHex(deal.contractId, 8)) : 'Offer: ' + escapeHtml(shortenHex(deal.offerId, 8))}</span>
            <span class="tag tag-cyan">\${escapeHtml(deal.status)}</span>
          </div>
          \${renderTimeline(deal)}
          <div class="deal-details-grid">
            <div class="detail-item">
              <span class="detail-k">Amount (Wei)</span>
              <span class="detail-v">\${escapeHtml(deal.amount)}</span>
            </div>
            <div class="detail-item">
              <span class="detail-k">Role (Session)</span>
              <span class="detail-v">\${isPayer ? 'Payer' : (isPayee ? 'Payee' : 'Observer')}</span>
            </div>
            <div class="detail-item">
              <span class="detail-k">Payer DID</span>
              <span class="detail-v">\${escapeHtml(shortenHex(deal.payer?.did || '—', 8))}</span>
            </div>
            <div class="detail-item">
              <span class="detail-k">Payee DID</span>
              <span class="detail-v">\${escapeHtml(shortenHex(deal.payee?.did || '—', 8))}</span>
            </div>
            \${deal.statement ? \`
            <div class="detail-item" style="grid-column: 1 / -1;">
              <span class="detail-k">Hashlock Statement</span>
              <span class="detail-v">\${escapeHtml(deal.statement)}</span>
            </div>\` : ''}
          </div>
          \${actions.length > 0 ? '<div class="deal-actions">' + actionsHtml + '</div>' : ''}
        </div>
      \`;
    }

    async function poll() {
      try {
        const [sessRes, balRes, msgsRes, dealsRes, archivesRes] = await Promise.all([
          fetch('/api/session'),
          fetch('/api/balance'),
          fetch('/api/messages'),
          fetch('/api/deals'),
          fetch('/api/archives')
        ]);

        if (sessRes.ok) {
          const sess = await sessRes.json();
          myDid = sess.did;
          myRole = sess.role;
          document.getElementById('session-did').textContent = shortenHex(sess.did, 8);
          document.getElementById('session-address').textContent = shortenHex(sess.evmAddress, 6);
          document.getElementById('session-role').textContent = sess.role.toUpperCase();
          document.getElementById('session-room').textContent = sess.room + ' (EVM ' + sess.chainId + ')';
          document.getElementById('room-badge').textContent = sess.room;
        }

        if (balRes.ok) {
          const bal = await balRes.json();
          document.getElementById('session-balance').textContent = bal.formatted + ' ETH';
        }

        if (msgsRes.ok) {
          const data = await msgsRes.json();
          const msgs = data.messages || [];
          const container = document.getElementById('messages-container');
          if (msgs.length === 0) {
            container.innerHTML = '<div class="empty-placeholder">No messages in room yet.</div>';
          } else {
            container.innerHTML = msgs.map(m => {
              let cls = 'msg-item';
              if (m.isSelf) cls += ' self';
              if (m.isProtocol) cls += ' protocol';
              const label = m.isProtocol ? ('[PROTOCOL: ' + (m.frameType || 'FRAME') + ']') : (m.isSelf ? 'You' : shortenHex(m.from, 6));
              const dt = new Date(m.ts).toLocaleTimeString();
              return \`
                <div class="\${cls}">
                  <div class="msg-header">
                    <span class="msg-author">\${escapeHtml(label)}</span>
                    <span>\${escapeHtml(dt)}</span>
                  </div>
                  <div class="msg-text">\${escapeHtml(m.text)}</div>
                </div>
              \`;
            }).join('');
            container.scrollTop = container.scrollHeight;
          }
        }

        if (dealsRes.ok) {
          const dealsData = await dealsRes.json();
          const allDeals = [...(dealsData.active || []), ...(dealsData.completed || [])];
          const container = document.getElementById('deals-list');
          if (allDeals.length === 0) {
            container.innerHTML = '<div class="empty-placeholder">No active or completed deals yet.</div>';
          } else {
            container.innerHTML = allDeals.map(renderDealCard).join('');
          }
        }
      } catch (err) {
        document.getElementById('pulse-dot').style.background = 'var(--accent-rose)';
        document.getElementById('connection-status').textContent = 'Disconnected';
      }
    }

    // Toggle Offer Form
    document.getElementById('toggle-offer-form').addEventListener('click', () => {
      const f = document.getElementById('offer-form');
      f.style.display = f.style.display === 'none' ? 'grid' : 'none';
    });

    document.getElementById('cancel-offer-btn').addEventListener('click', () => {
      document.getElementById('offer-form').style.display = 'none';
    });

    // Create Offer Submit
    document.getElementById('offer-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const amountEth = document.getElementById('offer-amount-eth').value.trim();
      const counterpartyDid = document.getElementById('offer-counterparty-did').value.trim();
      const claimBySec = parseInt(document.getElementById('offer-claim-sec').value, 10);
      const refundAfterSec = parseInt(document.getElementById('offer-refund-sec').value, 10);

      try {
        const res = await fetch('/api/deals/offer', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            amountEth,
            counterpartyDid: counterpartyDid || undefined,
            claimBySec,
            refundAfterSec,
            expiresSec: 300
          })
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.message || data.error || 'Failed to create offer');
        }
        showFeedback('Offer created successfully!');
        document.getElementById('offer-form').style.display = 'none';
        await poll();
      } catch (err) {
        showFeedback(err.message, true);
      }
    });

    // Send Chat Submit
    document.getElementById('chat-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const input = document.getElementById('chat-input');
      const text = input.value.trim();
      if (!text) return;

      try {
        const res = await fetch('/api/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text })
        });
        if (!res.ok) {
          const data = await res.json();
          throw new Error(data.message || data.error || 'Failed to send chat');
        }
        input.value = '';
        await poll();
      } catch (err) {
        showFeedback(err.message, true);
      }
    });

    poll();
    setInterval(poll, 2000);
  </script>
</body>
</html>`;
}

// -----------------------------------------------------------------------------
// DealWalletServer Implementation
// -----------------------------------------------------------------------------

export class DealWalletServer {
  public readonly app: DealWalletApp;
  public readonly host: string;
  public readonly port: number;
  public readonly syncIntervalMs: number;
  private _server: http.Server | null = null;
  private _actualPort: number = 0;
  private _syncTimer: NodeJS.Timeout | null = null;
  private _isSyncing: boolean = false;
  private _messageCache: SafeMessageDto[] = [];

  constructor(config: DealWalletServerConfig) {
    this.app = config.app;
    this.host = config.host ?? "127.0.0.1";
    this.port = config.port ?? 3456;
    this.syncIntervalMs = config.syncIntervalMs ?? 2000;

    // Strict loopback validation
    if (this.host !== "127.0.0.1" && this.host !== "localhost" && this.host !== "::1") {
      throw new Error(`DealWalletServer must bind to loopback address (127.0.0.1), got: ${this.host}`);
    }
  }

  get actualPort(): number {
    return this._actualPort || this.port;
  }

  get url(): string {
    return `http://${this.host}:${this.actualPort}`;
  }

  get server(): http.Server | null {
    return this._server;
  }

  get messageCache(): SafeMessageDto[] {
    return [...this._messageCache];
  }

  /**
   * Controlled background sync loop around app.sync().
   * Prevents overlapping syncs and recovers cleanly from transient failures.
   */
  public async triggerSync(): Promise<void> {
    if (this._isSyncing) return;
    this._isSyncing = true;
    try {
      await this.app.sync();
      await this.refreshMessageCache();
    } catch {
      // Recover cleanly from transient sync failures without crashing
    } finally {
      this._isSyncing = false;
    }
  }

  /**
   * Updates the presentation message cache from transport records.
   * Redacts any secret preimages and never exposes private keys/seeds/signatures.
   */
  private async refreshMessageCache(): Promise<void> {
    const raw = await this.app.transport.fetchMessages(this.app.room);
    const seen = new Set<string>();
    const safeList: SafeMessageDto[] = [];

    for (const r of raw) {
      const dedupKey = `${r.seq}-${r.from}-${r.nonce}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      const isProto = isTclkLine(r.text);
      let frameType: string | null = null;
      let contractOrOfferId: string | null = null;
      let safeText = r.text;

      if (isProto) {
        const frame = tryDecodeTclkFrame(r.text);
        if (frame) {
          frameType = frame.type;
          const frameObj = frame as unknown as Record<string, unknown>;
          if (typeof frameObj.contract === "string") {
            contractOrOfferId = frameObj.contract;
          } else if (typeof frameObj.id === "string") {
            contractOrOfferId = frameObj.id;
          } else if (typeof frameObj.ref === "string") {
            contractOrOfferId = frameObj.ref;
          }

          // Redact reveal secret so preimage NEVER appears in HTTP presentation responses
          if (frame.type === "reveal") {
            safeText = r.text.replace(/"secret"\s*:\s*"[^"]+"/g, '"secret":"[REDACTED]"');
          }
        }
      }

      safeList.push({
        seq: r.seq,
        ts: r.ts,
        from: r.from,
        isSelf: r.from === this.app.session.did,
        text: safeText,
        isProtocol: isProto,
        frameType,
        contractOrOfferId,
      });
    }

    // Preserve chronological ordering by seq
    safeList.sort((a, b) => a.seq - b.seq);
    this._messageCache = safeList;
  }

  /**
   * Starts the local HTTP loopback server and background sync timer.
   */
  async start(): Promise<{ host: string; port: number; url: string }> {
    if (this._server) {
      return { host: this.host, port: this.actualPort, url: this.url };
    }

    return new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => this.handleRequest(req, res));

      server.on("error", (err) => {
        reject(err);
      });

      server.listen(this.port, this.host, async () => {
        const addr = server.address();
        if (typeof addr === "object" && addr !== null) {
          this._actualPort = addr.port;
        } else {
          this._actualPort = this.port;
        }
        this._server = server;

        // Perform initial controlled sync
        await this.triggerSync();

        // Start background synchronization loop
        this._syncTimer = setInterval(() => {
          this.triggerSync().catch(() => {});
        }, this.syncIntervalMs);

        resolve({ host: this.host, port: this.actualPort, url: this.url });
      });
    });
  }

  /**
   * Shuts down the HTTP server cleanly and stops the background sync timer.
   */
  async stop(): Promise<void> {
    if (this._syncTimer) {
      clearInterval(this._syncTimer);
      this._syncTimer = null;
    }
    if (!this._server) return;
    return new Promise((resolve, reject) => {
      this._server!.close((err) => {
        this._server = null;
        if (err) reject(err);
        else resolve();
      });
    });
  }

  /**
   * Dispatches incoming HTTP requests with strict validation, CORS prevention,
   * CSP headers, and secure routing.
   */
  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const parsedUrl = new URL(req.url ?? "/", `http://${this.host}`);
    const pathname = parsedUrl.pathname;
    const method = req.method?.toUpperCase() ?? "GET";

    // Strict security headers on every response
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; font-src https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' 'unsafe-inline'; connect-src 'self'",
    );

    // Route matching
    const isDealAction = /^\/api\/deals\/([^/]+)\/(accept|lock|verify|reveal|claim|refund|cancel)$/.exec(pathname);

    try {
      // 1. Static & Presentation routes (GET / HEAD)
      if (pathname === "/" || pathname === "/index.html") {
        if (method !== "GET" && method !== "HEAD") {
          this.sendMethodNotAllowed(res, "GET, HEAD", pathname, method);
          return;
        }
        const html = renderDashboardHtml();
        res.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          "Content-Length": Buffer.byteLength(html),
        });
        if (method === "HEAD") res.end();
        else res.end(html);
        return;
      }

      if (pathname === "/api/health") {
        if (method !== "GET" && method !== "HEAD") {
          this.sendMethodNotAllowed(res, "GET, HEAD", pathname, method);
          return;
        }
        const data: HealthResponseDto = {
          status: "ok",
          uptime: process.uptime(),
          timestamp: Date.now(),
        };
        this.sendJsonResponse(res, 200, data, method === "HEAD");
        return;
      }

      if (pathname === "/api/session") {
        if (method !== "GET" && method !== "HEAD") {
          this.sendMethodNotAllowed(res, "GET, HEAD", pathname, method);
          return;
        }
        const data: SafeSessionMetadataDto = {
          did: this.app.session.did,
          evmAddress: this.app.session.evmAddress,
          chainId: this.app.session.chainId,
          role: this.app.session.role,
          htlcAddress: this.app.session.htlcAddress,
          room: this.app.room,
        };
        this.sendJsonResponse(res, 200, data, method === "HEAD");
        return;
      }

      if (pathname === "/api/balance") {
        if (method !== "GET" && method !== "HEAD") {
          this.sendMethodNotAllowed(res, "GET, HEAD", pathname, method);
          return;
        }
        const eth = await this.app.session.getEthBalance();
        const data: SafeBalanceDto = {
          balance: eth.balance.toString(),
          formatted: eth.formatted,
          chainId: this.app.session.chainId,
          evmAddress: this.app.session.evmAddress,
        };
        this.sendJsonResponse(res, 200, data, method === "HEAD");
        return;
      }

      if (pathname === "/api/deals") {
        if (method !== "GET" && method !== "HEAD") {
          this.sendMethodNotAllowed(res, "GET, HEAD", pathname, method);
          return;
        }
        const active = this.app.listActiveDeals().map(toSafeDealDto);
        const completed = this.app.listCompletedDeals().map(toSafeDealDto);
        const data: SafeDealsResponseDto = {
          active,
          completed,
          counts: {
            active: active.length,
            completed: completed.length,
            total: active.length + completed.length,
          },
        };
        this.sendJsonResponse(res, 200, data, method === "HEAD");
        return;
      }

      if (pathname === "/api/archives") {
        if (method !== "GET" && method !== "HEAD") {
          this.sendMethodNotAllowed(res, "GET, HEAD", pathname, method);
          return;
        }
        const archives = await this.app.listArchives();
        const data: SafeArchivesResponseDto = {
          archives,
          count: archives.length,
        };
        this.sendJsonResponse(res, 200, data, method === "HEAD");
        return;
      }

      // 2. Room Messages Endpoint (GET /api/messages)
      if (pathname === "/api/messages") {
        if (method !== "GET" && method !== "HEAD") {
          this.sendMethodNotAllowed(res, "GET, HEAD", pathname, method);
          return;
        }
        // Returns safe messages from in-memory cache without triggering remote fetch
        const data: SafeMessagesResponseDto = {
          messages: this.messageCache,
          count: this._messageCache.length,
        };
        this.sendJsonResponse(res, 200, data, method === "HEAD");
        return;
      }

      // 3. Room Chat Endpoint (POST /api/chat)
      if (pathname === "/api/chat") {
        if (method !== "POST") {
          this.sendMethodNotAllowed(res, "POST", pathname, method);
          return;
        }

        const body = await readJsonBody<{ text?: string }>(req);
        if (typeof body.text !== "string") {
          this.sendError(res, 400, "Bad Request", "Missing or invalid 'text' property in JSON payload");
          return;
        }

        const trimmed = body.text.trim();
        if (trimmed.length === 0) {
          this.sendError(res, 400, "Bad Request", "Chat text cannot be empty");
          return;
        }
        if (trimmed.length > 4096) {
          this.sendError(res, 400, "Bad Request", "Chat text exceeds maximum limit of 4096 characters");
          return;
        }

        // Delegate to orchestrator/session - never sign in HTTP layer
        await this.app.sendChat(trimmed);
        await this.triggerSync();

        this.sendJsonResponse(res, 200, { ok: true });
        return;
      }

      // 4. Deal Offer Endpoint (POST /api/deals/offer)
      if (pathname === "/api/deals/offer") {
        if (method !== "POST") {
          this.sendMethodNotAllowed(res, "POST", pathname, method);
          return;
        }

        const body = await readJsonBody<CreateOfferRequestDto>(req);

        if (!body || typeof body.amountEth !== "string" || !body.amountEth.trim()) {
          this.sendError(res, 400, "Bad Request", "Missing or invalid 'amountEth' string in request body");
          return;
        }

        // Exact integer conversion to wei using viem parseEther (no float arithmetic)
        let weiBigInt: bigint;
        try {
          weiBigInt = parseEther(body.amountEth.trim());
        } catch {
          this.sendError(res, 400, "Bad Request", `Invalid amount format: ${body.amountEth}`);
          return;
        }

        if (weiBigInt <= 0n) {
          this.sendError(res, 400, "Bad Request", "Amount must be strictly positive");
          return;
        }

        // Deadlines validation
        const claimBySec = typeof body.claimBySec === "number" ? body.claimBySec : 600;
        const refundAfterSec = typeof body.refundAfterSec === "number" ? body.refundAfterSec : 1200;
        const expiresSec = typeof body.expiresSec === "number" ? body.expiresSec : 300;

        if (claimBySec <= 0 || refundAfterSec <= 0 || expiresSec <= 0) {
          this.sendError(res, 400, "Bad Request", "Deadlines must be positive seconds");
          return;
        }

        if (claimBySec >= refundAfterSec) {
          this.sendError(res, 400, "Bad Request", "Strict ordering required: claimBySec must be less than refundAfterSec");
          return;
        }

        // Counterparty DID validation
        if (body.counterpartyDid !== undefined) {
          if (typeof body.counterpartyDid !== "string" || !body.counterpartyDid.startsWith("did:key:")) {
            this.sendError(res, 400, "Bad Request", "Invalid counterparty DID format; must start with did:key:");
            return;
          }
        }

        // Role validation against server wallet configured role
        const sessionRole = this.app.session.role;
        let role: "payer" | "payee" = "payer";
        if (body.role) {
          if (body.role !== "payer" && body.role !== "payee") {
            this.sendError(res, 400, "Bad Request", "Role must be 'payer' or 'payee'");
            return;
          }
          if (sessionRole === "payer" && body.role === "payee") {
            this.sendError(res, 400, "Bad Request", "Configured wallet role is payer; cannot create offer as payee");
            return;
          }
          if (sessionRole === "payee" && body.role === "payer") {
            this.sendError(res, 400, "Bad Request", "Configured wallet role is payee; cannot create offer as payer");
            return;
          }
          role = body.role;
        } else {
          role = sessionRole === "payee" ? "payee" : "payer";
        }

        const now = Date.now();
        const created = await this.app.createOffer({
          role,
          amount: weiBigInt.toString(),
          asset: "ETH",
          claimByMs: now + claimBySec * 1000,
          refundAfterMs: now + refundAfterSec * 1000,
          expiresMs: now + expiresSec * 1000,
          counterpartyDid: body.counterpartyDid,
        });

        // Trigger immediate sync
        await this.triggerSync();

        this.sendJsonResponse(res, 201, {
          ok: true,
          offerId: created.offerId,
          deal: toSafeDealDto(created.deal),
        });
        return;
      }

      // 5. Deal Action Endpoints (POST /api/deals/:id/action)
      if (isDealAction) {
        if (method !== "POST") {
          this.sendMethodNotAllowed(res, "POST", pathname, method);
          return;
        }

        const id = decodeURIComponent(isDealAction[1]);
        const action = isDealAction[2];

        // Consume body safely if any (e.g. cancel reason)
        const body = await readJsonBody<{ reason?: string }>(req);

        // Disallow browser from submitting secrets/preimages
        if ((body as any).secret || (body as any).preimage) {
          this.sendError(res, 400, "Bad Request", "Preimages and secrets are strictly managed server-side and cannot be submitted via HTTP");
          return;
        }

        switch (action) {
          case "accept": {
            await this.app.acceptDeal({ offerId: id });
            break;
          }
          case "lock": {
            await this.app.lockFunds(id);
            break;
          }
          case "verify": {
            await this.app.verifyLock(id);
            break;
          }
          case "reveal": {
            await this.app.revealSecret(id);
            break;
          }
          case "claim": {
            await this.app.claimFunds(id);
            break;
          }
          case "refund": {
            await this.app.refundDeal(id);
            break;
          }
          case "cancel": {
            await this.app.cancelDeal(id, body?.reason);
            break;
          }
        }

        // Trigger immediate sync to update deal states and messages
        await this.triggerSync();

        const updatedDeal = this.app.getDeal(id);
        const resDto: DealActionResponseDto = {
          ok: true,
          action,
          deal: updatedDeal ? toSafeDealDto(updatedDeal) : undefined,
        };
        this.sendJsonResponse(res, 200, resDto);
        return;
      }

      // Route Not Found
      this.sendError(res, 404, "Not Found", `Cannot ${method} ${pathname}`);
    } catch (err: unknown) {
      if (err instanceof HttpPayloadError) {
        this.sendError(res, err.statusCode, err.name, err.message);
        return;
      }

      if (err instanceof UnauthorizedActorError || err instanceof DealStateMismatchError) {
        this.sendError(res, 400, "Bad Request", sanitizeErrorMessage(err));
        return;
      }

      if (err instanceof OrchestratorError) {
        this.sendError(res, 400, "Bad Request", sanitizeErrorMessage(err));
        return;
      }

      // Default safe error response
      this.sendError(res, 500, "Internal Server Error", sanitizeErrorMessage(err));
    }
  }

  private sendJsonResponse(res: http.ServerResponse, status: number, body: unknown, isHead = false): void {
    const json = JSON.stringify(body);
    res.writeHead(status, {
      "Content-Type": "application/json; charset=utf-8",
      "Content-Length": Buffer.byteLength(json),
    });
    if (isHead) {
      res.end();
    } else {
      res.end(json);
    }
  }

  private sendError(res: http.ServerResponse, status: number, error: string, message: string): void {
    const payload = {
      error,
      message: sanitizeErrorMessage(message),
    };
    this.sendJsonResponse(res, status, payload);
  }

  private sendMethodNotAllowed(res: http.ServerResponse, allow: string, pathname: string, method: string): void {
    res.setHeader("Allow", allow);
    this.sendError(res, 405, "Method Not Allowed", `Method ${method} not allowed for ${pathname}`);
  }
}

// -----------------------------------------------------------------------------
// CLI Arguments Parsing & Startup Factory
// -----------------------------------------------------------------------------

export interface CliOptions {
  accountIndex: number;
  port: number;
  host: string;
  room: string;
  rpcUrl: string;
  htlcAddress?: Address;
  role?: SessionRole;
}

export function parseCliArgs(argv: string[] = process.argv.slice(2)): CliOptions {
  let accountIndex = 0;
  let port = 3456;
  let host = "127.0.0.1";
  let room = "default-room";
  let rpcUrl = "http://127.0.0.1:8545";
  let htlcAddress: Address | undefined;
  let role: SessionRole = "dual";

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--account" && i + 1 < argv.length) {
      accountIndex = parseInt(argv[++i], 10) || 0;
    } else if (arg === "--port" && i + 1 < argv.length) {
      port = parseInt(argv[++i], 10) || 3456;
    } else if (arg === "--host" && i + 1 < argv.length) {
      host = argv[++i];
    } else if (arg === "--room" && i + 1 < argv.length) {
      room = argv[++i];
    } else if (arg === "--rpc" && i + 1 < argv.length) {
      rpcUrl = argv[++i];
    } else if (arg === "--htlc" && i + 1 < argv.length) {
      htlcAddress = getAddress(argv[++i]);
    } else if (arg === "--role" && i + 1 < argv.length) {
      const val = argv[++i];
      if (val === "payer" || val === "payee" || val === "dual") {
        role = val;
      }
    }
  }

  return { accountIndex, port, host, room, rpcUrl, htlcAddress, role };
}

/**
 * Creates and starts a DealWalletServer using an Anvil account.
 */
export async function startDealWalletServer(options: CliOptions): Promise<DealWalletServer> {
  const publicClient = createPublicClient({
    chain: foundry,
    transport: viemHttp(options.rpcUrl),
  });

  const session = await WalletSession.fromAnvil(options.accountIndex, {
    htlcAddress: options.htlcAddress ?? "0x0000000000000000000000000000000000000000",
    rpcUrl: options.rpcUrl,
    publicClient,
    role: options.role ?? "dual",
  });

  const app = new DealWalletApp({
    session,
    room: options.room,
  });

  const server = new DealWalletServer({
    app,
    host: options.host,
    port: options.port,
  });

  await server.start();
  return server;
}

// -----------------------------------------------------------------------------
// Direct CLI Execution
// -----------------------------------------------------------------------------

const currentFileUrl = import.meta.url;
const executedFileUrl = process.argv[1] ? `file:///${path.resolve(process.argv[1]).replace(/\\/g, "/")}` : "";

if (currentFileUrl === executedFileUrl) {
  const opts = parseCliArgs();
  startDealWalletServer(opts)
    .then((srv) => {
      console.log(`=======================================================`);
      console.log(`⚡ Technocore Deal Wallet Server (Phase 4C-2)`);
      console.log(`=======================================================`);
      console.log(`URL:      ${srv.url}`);
      console.log(`DID:      ${srv.app.session.did}`);
      console.log(`Address:  ${srv.app.session.evmAddress}`);
      console.log(`Room:     ${srv.app.room}`);
      console.log(`Chain ID: ${srv.app.session.chainId}`);
      console.log(`Security: Bound to loopback ${srv.host}`);
      console.log(`=======================================================`);
    })
    .catch((err) => {
      console.error("Failed to start DealWalletServer:", err);
      process.exit(1);
    });
}
