// SPDX-License-Identifier: Apache-2.0

import * as fs from "node:fs";
import * as path from "node:path";
import { type Address, getAddress, isAddress } from "viem";
import {
  type DealArchive,
  verifyDealArchive,
  DealStatus,
} from "../index.js";
import {
  type AppConfig,
  type ContactEntry,
  type ArchivedDealSummary,
  type ArchiveStoreIndex,
  ArchiveStoreError,
  TamperedArchiveError,
  ArchiveNotFoundError,
  InvalidContactError,
  InsecureConfigError,
} from "./types.js";

export class ArchiveStore {
  public readonly rootDir: string;
  public readonly archivesDir: string;
  public readonly configPath: string;
  public readonly contactsPath: string;
  public readonly indexPath: string;

  constructor(rootDir = ".deal-wallet") {
    this.rootDir = path.resolve(process.cwd(), rootDir);
    this.archivesDir = path.join(this.rootDir, "archives");
    this.configPath = path.join(this.rootDir, "config.json");
    this.contactsPath = path.join(this.rootDir, "contacts.json");
    this.indexPath = path.join(this.rootDir, "index.json");
  }

  // ---------------------------------------------------------------------------
  // Store Initialization
  // ---------------------------------------------------------------------------

  async initialize(): Promise<void> {
    if (!fs.existsSync(this.rootDir)) {
      fs.mkdirSync(this.rootDir, { recursive: true });
    }
    if (!fs.existsSync(this.archivesDir)) {
      fs.mkdirSync(this.archivesDir, { recursive: true });
    }
    if (!fs.existsSync(this.contactsPath)) {
      await this.atomicWriteJson(this.contactsPath, { version: 1, contacts: {} });
    }
    if (!fs.existsSync(this.indexPath)) {
      await this.atomicWriteJson(this.indexPath, { version: 1, updatedAtMs: Date.now(), deals: {} });
    }
  }

  // ---------------------------------------------------------------------------
  // Atomic File Write Helper
  // ---------------------------------------------------------------------------

  private async atomicWriteJson(targetPath: string, data: unknown): Promise<void> {
    const parentDir = path.dirname(targetPath);
    if (!fs.existsSync(parentDir)) {
      fs.mkdirSync(parentDir, { recursive: true });
    }

    const tempPath = `${targetPath}.tmp.${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const jsonStr = JSON.stringify(data, null, 2);

    try {
      fs.writeFileSync(tempPath, jsonStr, "utf8");
      fs.renameSync(tempPath, targetPath);
    } catch (err) {
      if (fs.existsSync(tempPath)) {
        try {
          fs.unlinkSync(tempPath);
        } catch {
          // ignore cleanup error
        }
      }
      throw new ArchiveStoreError(`failed atomic write to ${targetPath}: ${(err as Error).message}`);
    }
  }

  // ---------------------------------------------------------------------------
  // Archive Operations
  // ---------------------------------------------------------------------------

  getArchiveFilePath(contractId: string): string {
    const cleanId = contractId.toLowerCase().replace(/[^a-f0-9x]/g, "");
    return path.join(this.archivesDir, `${cleanId}.archive.json`);
  }

  /**
   * Saves a terminal DealArchive to disk after offline cryptographic verification.
   * Updates index.json atomically.
   */
  async saveArchive(archive: DealArchive): Promise<ArchivedDealSummary> {
    await this.initialize();

    const contractId = archive.deal.contractId.toLowerCase();
    const status = archive.deal.status;

    // 1. Enforce terminal state
    const validTerminalStatuses = [
      DealStatus.CLAIMED,
      DealStatus.REFUNDED,
      DealStatus.CANCELLED,
    ];
    if (!validTerminalStatuses.includes(status as DealStatus)) {
      throw new ArchiveStoreError(
        `cannot store non-terminal deal archive (status: ${status})`,
      );
    }

    // 2. Cryptographic verification before saving
    const vResult = await verifyDealArchive(archive, { useCli: false });
    if (!vResult.valid) {
      throw new TamperedArchiveError(contractId, vResult.errors);
    }

    // 3. Atomic write archive file
    const targetFile = this.getArchiveFilePath(contractId);
    await this.atomicWriteJson(targetFile, archive);

    // 4. Update index safely
    const summary: ArchivedDealSummary = {
      contractId,
      room: archive.deal.room,
      status: archive.deal.status,
      payerDid: archive.deal.payer.did,
      payeeDid: archive.deal.payee.did,
      amount: archive.deal.terms?.amount as string | undefined,
      asset: archive.deal.terms?.asset as string | undefined,
      rail: archive.deal.rail,
      ref: archive.deal.ref,
      fileName: path.basename(targetFile),
      exportRoot: archive.commitment.export_root,
      archivedAtMs: archive.archivedAtMs ?? Date.now(),
      verifiedOffline: true,
    };

    const index = await this.loadIndex();
    index.deals[contractId] = summary;
    index.updatedAtMs = Date.now();
    await this.atomicWriteJson(this.indexPath, index);

    return summary;
  }

  /**
   * Loads an archive from disk and validates cryptographic authenticity offline.
   * If any record or proof is tampered with, throws TamperedArchiveError.
   */
  async loadArchive(contractId: string): Promise<DealArchive> {
    const filePath = this.getArchiveFilePath(contractId);
    if (!fs.existsSync(filePath)) {
      throw new ArchiveNotFoundError(contractId);
    }

    let archive: DealArchive;
    try {
      const raw = fs.readFileSync(filePath, "utf8");
      archive = JSON.parse(raw) as DealArchive;
    } catch (err) {
      throw new ArchiveStoreError(`corrupted archive JSON for ${contractId}: ${(err as Error).message}`);
    }

    // Always re-verify cryptographic integrity offline on load
    const vResult = await verifyDealArchive(archive, { useCli: false });
    if (!vResult.valid) {
      throw new TamperedArchiveError(contractId, vResult.errors);
    }

    return archive;
  }

  /**
   * Lists archived deals from index.json.
   * Checks file existence; does not trust stale index entries.
   */
  async listArchives(): Promise<ArchivedDealSummary[]> {
    const index = await this.loadIndex();
    const list: ArchivedDealSummary[] = [];

    for (const [id, summary] of Object.entries(index.deals)) {
      const file = this.getArchiveFilePath(id);
      if (fs.existsSync(file)) {
        list.push(summary);
      }
    }

    return list.sort((a, b) => b.archivedAtMs - a.archivedAtMs);
  }

  private async loadIndex(): Promise<ArchiveStoreIndex> {
    if (!fs.existsSync(this.indexPath)) {
      return { version: 1, updatedAtMs: Date.now(), deals: {} };
    }
    try {
      const raw = fs.readFileSync(this.indexPath, "utf8");
      return JSON.parse(raw) as ArchiveStoreIndex;
    } catch {
      return { version: 1, updatedAtMs: Date.now(), deals: {} };
    }
  }

  // ---------------------------------------------------------------------------
  // Contact Management (contacts.json)
  // ---------------------------------------------------------------------------

  async saveContact(contact: ContactEntry): Promise<void> {
    await this.initialize();

    if (!contact.did || !contact.did.startsWith("did:key:z6Mk")) {
      throw new InvalidContactError(`DID must start with did:key:z6Mk; got ${contact.did}`);
    }

    if (!contact.evmAddress || !isAddress(contact.evmAddress)) {
      throw new InvalidContactError(`invalid EVM address: ${contact.evmAddress}`);
    }

    const cleanAddress = getAddress(contact.evmAddress);
    const contactsMap = await this.loadContacts();

    contactsMap[contact.did.toLowerCase()] = {
      alias: contact.alias.trim() || contact.did.slice(0, 16),
      did: contact.did,
      evmAddress: cleanAddress,
      updatedAtMs: Date.now(),
    };

    await this.atomicWriteJson(this.contactsPath, { version: 1, contacts: contactsMap });
  }

  async loadContacts(): Promise<Record<string, ContactEntry>> {
    if (!fs.existsSync(this.contactsPath)) {
      return {};
    }
    try {
      const raw = fs.readFileSync(this.contactsPath, "utf8");
      const parsed = JSON.parse(raw);
      return parsed.contacts ?? {};
    } catch {
      return {};
    }
  }

  async resolveContact(did: string): Promise<Address | null> {
    const contacts = await this.loadContacts();
    const found = contacts[did.toLowerCase()];
    return found ? found.evmAddress : null;
  }

  // ---------------------------------------------------------------------------
  // Non-Sensitive Configuration (config.json)
  // ---------------------------------------------------------------------------

  async saveConfig(config: AppConfig): Promise<void> {
    await this.initialize();

    // Enforce RPC URL safety: reject embedded credentials
    try {
      const parsedUrl = new URL(config.rpcUrl);
      if (parsedUrl.username || parsedUrl.password) {
        throw new InsecureConfigError("RPC URL must not contain embedded user:password credentials");
      }
    } catch (err) {
      if (err instanceof InsecureConfigError) throw err;
      throw new InsecureConfigError(`malformed RPC URL: ${config.rpcUrl}`);
    }

    if (!isAddress(config.htlcAddress)) {
      throw new InsecureConfigError(`invalid HTLC address: ${config.htlcAddress}`);
    }

    const safeConfig: AppConfig = {
      rpcUrl: config.rpcUrl,
      chainId: config.chainId,
      htlcAddress: getAddress(config.htlcAddress),
      updatedAtMs: Date.now(),
    };

    await this.atomicWriteJson(this.configPath, safeConfig);
  }

  async loadConfig(): Promise<AppConfig | null> {
    if (!fs.existsSync(this.configPath)) {
      return null;
    }
    try {
      const raw = fs.readFileSync(this.configPath, "utf8");
      return JSON.parse(raw) as AppConfig;
    } catch {
      return null;
    }
  }
}
