// SPDX-License-Identifier: Apache-2.0

import * as http from "node:http";
import { URL } from "node:url";
import * as path from "node:path";
import { createPublicClient, http as viemHttp, type Address, getAddress } from "viem";
import { foundry } from "viem/chains";
import { DealManager, DealStatus } from "../deal.js";
import { WalletSession } from "./session.js";
import { DealWalletApp } from "./orchestrator.js";
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
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
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

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg-base);
      background-image: 
        radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0, 242, 254, 0.12), transparent),
        radial-gradient(ellipse 60% 40% at 90% 80%, rgba(79, 172, 254, 0.06), transparent);
      color: var(--text-primary);
      font-family: var(--font-sans);
      min-height: 100vh;
      line-height: 1.5;
      padding: 24px;
    }

    .container {
      max-width: 1280px;
      margin: 0 auto;
    }

    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 24px;
      margin-bottom: 24px;
      border-bottom: 1px solid var(--border-subtle);
      flex-wrap: wrap;
      gap: 16px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .brand-icon {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 20px rgba(0, 242, 254, 0.35);
      font-weight: 800;
      color: #040810;
      font-size: 20px;
    }

    .brand-title {
      font-size: 20px;
      font-weight: 800;
      letter-spacing: -0.02em;
    }

    .brand-subtitle {
      font-size: 12px;
      color: var(--text-secondary);
      font-family: var(--font-mono);
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }

    .status-bar {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .badge-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 14px;
      border-radius: 9999px;
      font-size: 12px;
      font-family: var(--font-mono);
      font-weight: 600;
      background: rgba(15, 23, 42, 0.8);
      border: 1px solid var(--border-subtle);
    }

    .pulse-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background-color: var(--accent-emerald);
      box-shadow: 0 0 8px var(--accent-emerald);
      animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.5; transform: scale(0.85); }
    }

    .pulse-dot.error {
      background-color: var(--accent-rose);
      box-shadow: 0 0 8px var(--accent-rose);
    }

    /* Grid Layout */
    .dashboard-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
      gap: 20px;
      margin-bottom: 32px;
    }

    .card {
      background: var(--bg-card);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-subtle);
      border-radius: 16px;
      padding: 24px;
      transition: all 0.2s ease;
      position: relative;
      overflow: hidden;
    }

    .card:hover {
      border-color: var(--border-focus);
      background: var(--bg-card-hover);
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35);
    }

    .card-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      font-weight: 700;
      margin-bottom: 12px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .card-value-large {
      font-size: 32px;
      font-weight: 800;
      letter-spacing: -0.02em;
      color: var(--text-primary);
      margin-bottom: 8px;
      display: flex;
      align-items: baseline;
      gap: 8px;
    }

    .card-value-large .unit {
      font-size: 16px;
      font-weight: 600;
      color: var(--accent-cyan);
    }

    .info-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
      margin-top: 16px;
    }

    .info-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 13px;
      gap: 12px;
    }

    .info-label {
      color: var(--text-secondary);
    }

    .info-val {
      font-family: var(--font-mono);
      color: var(--text-primary);
      display: flex;
      align-items: center;
      gap: 6px;
      text-align: right;
      word-break: break-all;
    }

    .copy-btn {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-subtle);
      color: var(--text-secondary);
      cursor: pointer;
      padding: 2px 8px;
      border-radius: 6px;
      font-size: 11px;
      font-family: var(--font-sans);
      transition: all 0.15s ease;
    }

    .copy-btn:hover {
      background: rgba(0, 242, 254, 0.15);
      color: var(--accent-cyan);
      border-color: rgba(0, 242, 254, 0.3);
    }

    .tag {
      padding: 2px 8px;
      border-radius: 6px;
      font-size: 11px;
      font-family: var(--font-mono);
      font-weight: 600;
      text-transform: uppercase;
    }

    .tag-cyan { background: rgba(0, 242, 254, 0.12); color: var(--accent-cyan); border: 1px solid rgba(0, 242, 254, 0.25); }
    .tag-emerald { background: rgba(16, 185, 129, 0.12); color: var(--accent-emerald); border: 1px solid rgba(16, 185, 129, 0.25); }
    .tag-amber { background: rgba(245, 158, 11, 0.12); color: var(--accent-amber); border: 1px solid rgba(245, 158, 11, 0.25); }
    .tag-purple { background: rgba(139, 92, 246, 0.12); color: var(--accent-purple); border: 1px solid rgba(139, 92, 246, 0.25); }
    .tag-rose { background: rgba(244, 63, 94, 0.12); color: var(--accent-rose); border: 1px solid rgba(244, 63, 94, 0.25); }
    .tag-slate { background: rgba(148, 163, 184, 0.12); color: var(--text-secondary); border: 1px solid rgba(148, 163, 184, 0.25); }

    /* Section Tabs & Content */
    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
      flex-wrap: wrap;
      gap: 12px;
    }

    .section-title {
      font-size: 18px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .section-tabs {
      display: flex;
      gap: 8px;
      background: rgba(15, 23, 42, 0.6);
      padding: 4px;
      border-radius: 10px;
      border: 1px solid var(--border-subtle);
    }

    .tab-btn {
      background: transparent;
      border: none;
      color: var(--text-secondary);
      padding: 6px 14px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      font-family: var(--font-sans);
      transition: all 0.15s ease;
    }

    .tab-btn.active {
      background: rgba(255, 255, 255, 0.08);
      color: var(--text-primary);
      box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    }

    .deal-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .deal-card {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      padding: 16px 20px;
      display: grid;
      grid-template-columns: auto 1fr auto auto;
      align-items: center;
      gap: 20px;
      transition: border-color 0.15s ease;
    }

    .deal-card:hover {
      border-color: var(--border-focus);
    }

    .deal-id-group {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .deal-contract-id {
      font-family: var(--font-mono);
      font-weight: 600;
      font-size: 13px;
      color: var(--text-primary);
    }

    .deal-sub {
      font-size: 12px;
      color: var(--text-muted);
      font-family: var(--font-mono);
    }

    .deal-amount-group {
      text-align: right;
    }

    .deal-amount {
      font-weight: 700;
      font-size: 16px;
      color: var(--text-primary);
    }

    .empty-state {
      padding: 48px 24px;
      text-align: center;
      background: var(--bg-card);
      border: 1px dashed var(--border-subtle);
      border-radius: 16px;
      color: var(--text-muted);
      font-size: 14px;
    }

    .archive-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }

    .archive-table th {
      text-align: left;
      padding: 12px 16px;
      color: var(--text-muted);
      font-weight: 600;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 1px solid var(--border-subtle);
    }

    .archive-table td {
      padding: 14px 16px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    }

    .archive-table tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }

    footer {
      margin-top: 48px;
      padding-top: 24px;
      border-top: 1px solid var(--border-subtle);
      display: flex;
      justify-content: space-between;
      color: var(--text-muted);
      font-size: 12px;
      font-family: var(--font-mono);
      flex-wrap: wrap;
      gap: 12px;
    }

    @media (max-width: 768px) {
      body { padding: 16px; }
      .deal-card { grid-template-columns: 1fr; gap: 12px; }
      .deal-amount-group { text-align: left; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <div class="brand-icon">⚡</div>
        <div>
          <div class="brand-title">Technocore Deal Wallet</div>
          <div class="brand-subtitle">tclk/1 EVM Settlement Rail</div>
        </div>
      </div>
      <div class="status-bar">
        <div class="badge-pill">
          <span id="pulse-dot" class="pulse-dot"></span>
          <span id="connection-status">Connecting...</span>
        </div>
        <div class="badge-pill">
          <span style="color: var(--text-muted);">HOST</span>
          <span id="server-host">127.0.0.1</span>
        </div>
      </div>
    </header>

    <main>
      <!-- Top Cards -->
      <div class="dashboard-grid">
        <!-- Wallet Card -->
        <div class="card">
          <div class="card-label">
            <span>Identity & Balance</span>
            <span id="session-role" class="tag tag-cyan">DUAL</span>
          </div>
          <div class="card-value-large">
            <span id="eth-balance">0.0000</span>
            <span class="unit">ETH</span>
          </div>
          <div class="info-list">
            <div class="info-row">
              <span class="info-label">EVM Address</span>
              <span class="info-val">
                <span id="evm-address">0x000...000</span>
                <button class="copy-btn" onclick="copyText('evm-address-full')">Copy</button>
              </span>
            </div>
            <div class="info-row">
              <span class="info-label">Technocore DID</span>
              <span class="info-val">
                <span id="wallet-did">did:key:...</span>
                <button class="copy-btn" onclick="copyText('wallet-did-full')">Copy</button>
              </span>
            </div>
            <div class="info-row">
              <span class="info-label">Chain ID</span>
              <span class="info-val">
                <span id="chain-id" class="tag tag-slate">31337</span>
              </span>
            </div>
          </div>
        </div>

        <!-- Room & HTLC Card -->
        <div class="card">
          <div class="card-label">
            <span>Settlement Environment</span>
            <span class="tag tag-emerald">ONLINE</span>
          </div>
          <div class="card-value-large">
            <span id="room-name" style="font-size: 24px; font-family: var(--font-mono); color: var(--accent-blue);">--</span>
          </div>
          <div class="info-list">
            <div class="info-row">
              <span class="info-label">HTLC Contract</span>
              <span class="info-val">
                <span id="htlc-address">0x000...000</span>
                <button class="copy-btn" onclick="copyText('htlc-address-full')">Copy</button>
              </span>
            </div>
            <div class="info-row">
              <span class="info-label">Sync Protocol</span>
              <span class="info-val" style="color: var(--accent-cyan);">tclk/1 Live Stream</span>
            </div>
            <div class="info-row">
              <span class="info-label">Last Poll</span>
              <span id="last-poll" class="info-val">Just now</span>
            </div>
          </div>
        </div>

        <!-- Metrics Card -->
        <div class="card">
          <div class="card-label">
            <span>Lifecycle Metrics</span>
            <span class="tag tag-purple">STATS</span>
          </div>
          <div class="card-value-large">
            <span id="active-deals-count">0</span>
            <span class="unit" style="color: var(--text-secondary); font-size: 14px;">Active / <span id="completed-deals-count">0</span> Closed</span>
          </div>
          <div class="info-list">
            <div class="info-row">
              <span class="info-label">Verified Archives</span>
              <span class="info-val">
                <span id="archives-count" class="tag tag-emerald">0 Offline Verified</span>
              </span>
            </div>
            <div class="info-row">
              <span class="info-label">Loopback Security</span>
              <span class="info-val" style="color: var(--accent-emerald);">Strict Localhost Only</span>
            </div>
            <div class="info-row">
              <span class="info-label">Server Uptime</span>
              <span id="server-uptime" class="info-val">0s</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Deals Section -->
      <div style="margin-bottom: 40px;">
        <div class="section-header">
          <div class="section-title">
            <span>Deals Overview</span>
          </div>
          <div class="section-tabs">
            <button id="tab-active" class="tab-btn active" onclick="switchDealsTab('active')">Active Deals (<span id="tab-active-count">0</span>)</button>
            <button id="tab-completed" class="tab-btn" onclick="switchDealsTab('completed')">Completed (<span id="tab-completed-count">0</span>)</button>
          </div>
        </div>

        <div id="deals-active-container" class="deal-list">
          <div class="empty-state">No active deals currently in room.</div>
        </div>

        <div id="deals-completed-container" class="deal-list" style="display: none;">
          <div class="empty-state">No completed deals yet.</div>
        </div>
      </div>

      <!-- Archives Section -->
      <div>
        <div class="section-header">
          <div class="section-title">
            <span>Verified Cryptographic Archives</span>
          </div>
          <div>
            <span id="archives-summary-tag" class="tag tag-slate">0 Stored</span>
          </div>
        </div>

        <div class="card" style="padding: 0; overflow-x: auto;">
          <table class="archive-table">
            <thead>
              <tr>
                <th>Contract ID</th>
                <th>Room</th>
                <th>Status</th>
                <th>Integrity</th>
                <th>Export Root</th>
                <th>Archived At</th>
              </tr>
            </thead>
            <tbody id="archives-table-body">
              <tr>
                <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 32px;">No archives stored yet.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </main>

    <footer>
      <div>Technocore Deal Wallet &bull; Phase 4C-1 Local Node</div>
      <div>Security: Loopback Binding &bull; Zero Browser Credential Exposure</div>
    </footer>
  </div>

  <!-- Hidden elements for full string copying -->
  <input type="hidden" id="evm-address-full" value="">
  <input type="hidden" id="wallet-did-full" value="">
  <input type="hidden" id="htlc-address-full" value="">

  <script>
    // Strict HTML escaping to prevent XSS injection from user-controlled content
    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function shortenHex(hex, head = 6, tail = 4) {
      if (!hex || hex.length <= head + tail) return hex || '';
      return hex.slice(0, head) + '...' + hex.slice(-tail);
    }

    function shortenDid(did, head = 12, tail = 6) {
      if (!did || did.length <= head + tail) return did || '';
      return did.slice(0, head) + '...' + did.slice(-tail);
    }

    function copyText(elementId) {
      const el = document.getElementById(elementId);
      if (!el || !el.value) return;
      navigator.clipboard.writeText(el.value).then(() => {
        const btn = event.target;
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = originalText; }, 1200);
      });
    }

    let activeTab = 'active';
    function switchDealsTab(tab) {
      activeTab = tab;
      const activeBtn = document.getElementById('tab-active');
      const completedBtn = document.getElementById('tab-completed');
      const activeContainer = document.getElementById('deals-active-container');
      const completedContainer = document.getElementById('deals-completed-container');

      if (tab === 'active') {
        activeBtn.classList.add('active');
        completedBtn.classList.remove('active');
        activeContainer.style.display = 'flex';
        completedContainer.style.display = 'none';
      } else {
        completedBtn.classList.add('active');
        activeBtn.classList.remove('active');
        activeContainer.style.display = 'none';
        completedContainer.style.display = 'flex';
      }
    }

    function getStatusTagClass(status) {
      switch (status) {
        case 'OFFERED': return 'tag-amber';
        case 'ACCEPTED': return 'tag-cyan';
        case 'LOCKED': return 'tag-purple';
        case 'VERIFIED': return 'tag-cyan';
        case 'REVEALED': return 'tag-amber';
        case 'CLAIMED': return 'tag-emerald';
        case 'REFUNDED': return 'tag-rose';
        case 'CANCELLED': return 'tag-slate';
        default: return 'tag-slate';
      }
    }

    function renderDealCard(deal) {
      const displayId = deal.contractId ? shortenHex(deal.contractId) : shortenHex(deal.offerId);
      const isContract = Boolean(deal.contractId);
      const statusClass = getStatusTagClass(deal.status);
      const safeAmount = escapeHtml(deal.amount);
      const safeAsset = escapeHtml(deal.asset);
      const safeRole = escapeHtml(deal.role.toUpperCase());
      const safePayer = escapeHtml(shortenDid(deal.payer?.did || 'Unknown'));
      const safePayee = escapeHtml(shortenDid(deal.payee?.did || 'Unknown'));
      const safeStatement = deal.statement ? escapeHtml(shortenHex(deal.statement)) : 'Pending';

      return \`
        <div class="deal-card">
          <div class="deal-id-group">
            <div class="deal-contract-id">\${escapeHtml(displayId)}</div>
            <div class="deal-sub">\${isContract ? 'Contract' : 'Offer'} &bull; Lock: \${escapeHtml(deal.lock)}</div>
          </div>
          <div>
            <span class="tag \${statusClass}">\${escapeHtml(deal.status)}</span>
            <span class="tag tag-slate" style="margin-left: 6px;">\${safeRole}</span>
          </div>
          <div style="font-size: 12px; color: var(--text-secondary);">
            <div>Payer: <span style="font-family: var(--font-mono); color: var(--text-primary);">\${safePayer}</span></div>
            <div>Payee: <span style="font-family: var(--font-mono); color: var(--text-primary);">\${safePayee}</span></div>
          </div>
          <div class="deal-amount-group">
            <div class="deal-amount">\${safeAmount} \${safeAsset}</div>
            <div class="deal-sub">Hashlock: \${safeStatement}</div>
          </div>
        </div>
      \`;
    }

    async function pollDashboard() {
      try {
        const [healthRes, sessionRes, balanceRes, dealsRes, archivesRes] = await Promise.all([
          fetch('/api/health'),
          fetch('/api/session'),
          fetch('/api/balance'),
          fetch('/api/deals'),
          fetch('/api/archives'),
        ]);

        if (healthRes.ok && sessionRes.ok) {
          document.getElementById('pulse-dot').className = 'pulse-dot';
          document.getElementById('connection-status').textContent = 'Connected (Loopback)';
          
          const health = await healthRes.json();
          const uptimeSec = Math.floor(health.uptime || 0);
          document.getElementById('server-uptime').textContent = uptimeSec + 's';
        } else {
          throw new Error('Server health error');
        }

        if (sessionRes.ok) {
          const session = await sessionRes.json();
          document.getElementById('wallet-did').textContent = shortenDid(session.did);
          document.getElementById('wallet-did-full').value = session.did || '';
          document.getElementById('evm-address').textContent = shortenHex(session.evmAddress);
          document.getElementById('evm-address-full').value = session.evmAddress || '';
          document.getElementById('chain-id').textContent = session.chainId || '31337';
          document.getElementById('session-role').textContent = (session.role || 'DUAL').toUpperCase();
          document.getElementById('room-name').textContent = session.room || 'None';
          document.getElementById('htlc-address').textContent = shortenHex(session.htlcAddress);
          document.getElementById('htlc-address-full').value = session.htlcAddress || '';
        }

        if (balanceRes.ok) {
          const balance = await balanceRes.json();
          const formatted = parseFloat(balance.formatted || 0).toFixed(4);
          document.getElementById('eth-balance').textContent = formatted;
        }

        if (dealsRes.ok) {
          const deals = await dealsRes.json();
          const active = deals.active || [];
          const completed = deals.completed || [];

          document.getElementById('active-deals-count').textContent = active.length;
          document.getElementById('completed-deals-count').textContent = completed.length;
          document.getElementById('tab-active-count').textContent = active.length;
          document.getElementById('tab-completed-count').textContent = completed.length;

          const activeContainer = document.getElementById('deals-active-container');
          if (active.length === 0) {
            activeContainer.innerHTML = '<div class="empty-state">No active deals currently in room.</div>';
          } else {
            activeContainer.innerHTML = active.map(renderDealCard).join('');
          }

          const completedContainer = document.getElementById('deals-completed-container');
          if (completed.length === 0) {
            completedContainer.innerHTML = '<div class="empty-state">No completed deals yet.</div>';
          } else {
            completedContainer.innerHTML = completed.map(renderDealCard).join('');
          }
        }

        if (archivesRes.ok) {
          const archivesData = await archivesRes.json();
          const list = archivesData.archives || [];
          document.getElementById('archives-count').textContent = list.length + ' Offline Verified';
          document.getElementById('archives-summary-tag').textContent = list.length + ' Stored';

          const tbody = document.getElementById('archives-table-body');
          if (list.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 32px;">No archives stored yet.</td></tr>';
          } else {
            tbody.innerHTML = list.map(item => {
              const dt = new Date(item.archivedAtMs).toLocaleTimeString();
              return \`
                <tr>
                  <td style="font-family: var(--font-mono); font-weight: 600;">\${escapeHtml(shortenHex(item.contractId))}</td>
                  <td style="font-family: var(--font-mono);">\${escapeHtml(item.room)}</td>
                  <td><span class="tag \${getStatusTagClass(item.status)}">\${escapeHtml(item.status)}</span></td>
                  <td><span class="tag tag-emerald">✓ Offline Verified</span></td>
                  <td style="font-family: var(--font-mono); color: var(--text-secondary);">\${escapeHtml(shortenHex(item.exportRoot || ''))}</td>
                  <td style="color: var(--text-muted); font-size: 12px;">\${escapeHtml(dt)}</td>
                </tr>
              \`;
            }).join('');
          }
        }

        document.getElementById('last-poll').textContent = new Date().toLocaleTimeString();
      } catch (err) {
        document.getElementById('pulse-dot').className = 'pulse-dot error';
        document.getElementById('connection-status').textContent = 'Disconnected';
      }
    }

    // Initial poll and recurring 2.5s polling loop
    pollDashboard();
    setInterval(pollDashboard, 2500);
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
  private _server: http.Server | null = null;
  private _actualPort: number = 0;

  constructor(config: DealWalletServerConfig) {
    this.app = config.app;
    this.host = config.host ?? "127.0.0.1";
    this.port = config.port ?? 3456;

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

  /**
   * Starts the local HTTP loopback server.
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

      server.listen(this.port, this.host, () => {
        const addr = server.address();
        if (typeof addr === "object" && addr !== null) {
          this._actualPort = addr.port;
        } else {
          this._actualPort = this.port;
        }
        this._server = server;
        resolve({ host: this.host, port: this.actualPort, url: this.url });
      });
    });
  }

  /**
   * Shuts down the HTTP server cleanly.
   */
  async stop(): Promise<void> {
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
   * Dispatches incoming HTTP requests with strict method and routing validation.
   */
  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const parsedUrl = new URL(req.url ?? "/", `http://${this.host}`);
    const pathname = parsedUrl.pathname;
    const method = req.method?.toUpperCase() ?? "GET";

    // Set strict baseline security headers on every response
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");

    // Standard allowed routes
    const allowedRoutes = ["/", "/index.html", "/api/health", "/api/session", "/api/balance", "/api/deals", "/api/archives"];

    if (!allowedRoutes.includes(pathname)) {
      res.writeHead(404, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ error: "Not Found", message: `Cannot ${method} ${pathname}` }));
      return;
    }

    // Phase 4C-1 strictly supports GET and HEAD for read-only operations
    if (method !== "GET" && method !== "HEAD") {
      res.writeHead(405, {
        "Content-Type": "application/json; charset=utf-8",
        "Allow": "GET, HEAD",
      });
      res.end(JSON.stringify({ error: "Method Not Allowed", message: `Method ${method} not allowed for ${pathname}` }));
      return;
    }

    try {
      if (pathname === "/" || pathname === "/index.html") {
        const html = renderDashboardHtml();
        res.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          "Content-Length": Buffer.byteLength(html),
        });
        if (method === "HEAD") {
          res.end();
        } else {
          res.end(html);
        }
        return;
      }

      if (pathname === "/api/health") {
        const data: HealthResponseDto = {
          status: "ok",
          uptime: process.uptime(),
          timestamp: Date.now(),
        };
        this.sendJsonResponse(res, 200, data, method === "HEAD");
        return;
      }

      if (pathname === "/api/session") {
        // Return ONLY safe public metadata
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
        const archives = await this.app.listArchives();
        const data: SafeArchivesResponseDto = {
          archives,
          count: archives.length,
        };
        this.sendJsonResponse(res, 200, data, method === "HEAD");
        return;
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.writeHead(500, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ error: "Internal Server Error", message }));
    }
  }

  private sendJsonResponse(res: http.ServerResponse, status: number, body: unknown, isHead: boolean): void {
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
const executedFileUrl = process.argv[1] ? `file:///${path.resolve(process.argv[1]).replace(/\\\\/g, "/")}` : "";

if (currentFileUrl === executedFileUrl) {
  const opts = parseCliArgs();
  startDealWalletServer(opts)
    .then((srv) => {
      console.log(`=======================================================`);
      console.log(`⚡ Technocore Deal Wallet Server (Phase 4C-1)`);
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
