// SPDX-License-Identifier: Apache-2.0

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createHash } from "node:crypto";
import { DealManager, type DealRecord, DealValidationError } from "./deal.js";
import { sweptText, TechnocoreSigner } from "./transport.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { base58, base64urlnopad } from "@scure/base";

const execFileAsync = promisify(execFile);

// -----------------------------------------------------------------------------
// Type Definitions matching TC Ledger v1 Specification
// -----------------------------------------------------------------------------

export interface TcExportCommitment {
  schema: "tc-ledger/commitment/v1";
  version: number;
  profile: string;
  room: string;
  line_count: number;
  byte_count: number;
  file_sha256: string;
  export_root: string;
  verification: {
    VALID: number;
    INVALID: number;
    UNSIGNED: number;
    MALFORMED: number;
    UNSUPPORTED_KEY: number;
  };
  anomaly_indices: number[];
}

export interface TcAuditStep {
  position: "left" | "right";
  sibling_hash: string;
}

export interface TcInclusionProof {
  schema: "tc-ledger/inclusion-proof/v1";
  version: number;
  profile: string;
  room: string;
  export_generation: number;
  leaf_index: number;
  tree_size: number;
  leaf_hash: string;
  export_root: string;
  audit_path: TcAuditStep[];
}

export interface ArchivedDealStageRecord {
  stage: string;
  seq: number;
  leafIndex: number;
  rawLine: string; // Exact raw line bytes preserved as UTF-8 string with trailing newline
  leafHash: string; // RFC 6962 leaf hash: sha256(0x00 || raw_line_bytes)
  proof: TcInclusionProof;
}

export interface DealArchive {
  schema: "technocore/deal-archive/v1";
  version: 1;
  archivedAtMs: number;
  deal: {
    contractId: string;
    room: string;
    status: string;
    payer: { did: string; evmAddress?: string };
    payee: { did: string; evmAddress?: string };
    terms?: Record<string, unknown>;
    rail?: string;
    ref?: string;
    createdAtMs: number;
    updatedAtMs: number;
  };
  commitment: TcExportCommitment;
  records: Record<string, ArchivedDealStageRecord>;
  settlementEvidence?: {
    settlementRail?: string;
    settlementRef?: string;
    onChainVerified?: boolean;
    disclaimer: string;
  };
  verificationSummary: {
    verifiedOffline: boolean;
    trustModel: {
      provesRoomInclusion: true;
      provesSenderAuthenticity: true;
      provesOnChainSettlement: false;
      notice: string;
    };
  };
}

export interface ArchiveOptions {
  pythonPath?: string;
  allowIncomplete?: boolean;
  onChainVerified?: boolean;
  settlementRef?: string;
}

export interface VerificationResult {
  valid: boolean;
  errors: string[];
  stagesVerified: string[];
}

export class DealArchivalError extends Error {
  constructor(message: string) {
    super(`deal-archival: ${message}`);
    this.name = "DealArchivalError";
  }
}

// -----------------------------------------------------------------------------
// RFC 6962 Cryptographic Primitives (TypeScript reference implementation)
// -----------------------------------------------------------------------------

/**
 * Computes RFC 6962 leaf hash: SHA-256(0x00 || raw_line_bytes).
 */
export function computeLeafHash(rawLineBytes: Uint8Array): string {
  const hasher = createHash("sha256");
  hasher.update(Buffer.from([0x00]));
  hasher.update(rawLineBytes);
  return hasher.digest("hex");
}

/**
 * Computes RFC 6962 interior node hash: SHA-256(0x01 || left || right).
 */
export function computeNodeHash(left: Uint8Array, right: Uint8Array): Buffer {
  const hasher = createHash("sha256");
  hasher.update(Buffer.from([0x01]));
  hasher.update(left);
  hasher.update(right);
  return hasher.digest();
}

/**
 * Verifies an inclusion proof in-memory against raw record bytes and expected root.
 */
export function verifyInclusionProofInMemory(
  proof: TcInclusionProof,
  rawRecordBytes: Uint8Array,
  expectedRoot?: string,
  expectedRoom?: string,
): boolean {
  if (expectedRoom && proof.room !== expectedRoom) {
    return false;
  }
  const rootToCheck = expectedRoot ?? proof.export_root;
  if (proof.export_root.toLowerCase() !== rootToCheck.toLowerCase()) {
    return false;
  }

  // 1. Verify leaf hash
  const computedLeafHash = computeLeafHash(rawRecordBytes);
  if (computedLeafHash.toLowerCase() !== proof.leaf_hash.toLowerCase()) {
    return false;
  }

  // 2. Traverse audit path
  let currentHash: Buffer = Buffer.from(proof.leaf_hash, "hex");
  for (const step of proof.audit_path) {
    const siblingHash = Buffer.from(step.sibling_hash, "hex");
    if (step.position === "left") {
      currentHash = computeNodeHash(siblingHash, currentHash);
    } else if (step.position === "right") {
      currentHash = computeNodeHash(currentHash, siblingHash);
    } else {
      return false;
    }
  }

  return currentHash.toString("hex").toLowerCase() === rootToCheck.toLowerCase();
}

// -----------------------------------------------------------------------------
// Helper: Raw JSONL Line Slicing
// -----------------------------------------------------------------------------

/**
 * Slices raw export file into exact lines preserving trailing newlines and byte identity.
 */
export function sliceRawExportLines(exportBytes: Buffer): { buffer: Buffer; str: string }[] {
  const lines: { buffer: Buffer; str: string }[] = [];
  let start = 0;
  for (let i = 0; i < exportBytes.length; i++) {
    if (exportBytes[i] === 0x0a) {
      // '\n'
      const lineBuf = exportBytes.subarray(start, i + 1);
      lines.push({
        buffer: lineBuf,
        str: lineBuf.toString("utf8"),
      });
      start = i + 1;
    }
  }
  if (start < exportBytes.length) {
    // Last line without newline
    const lineBuf = exportBytes.subarray(start);
    lines.push({
      buffer: lineBuf,
      str: lineBuf.toString("utf8"),
    });
  }
  return lines;
}

// -----------------------------------------------------------------------------
// Technocore Ed25519 Record Signature Verifier
// -----------------------------------------------------------------------------

/**
 * Creates a signed export record matching TC Ledger's format:
 * `canonical = f"{room}|{nonce}|{record['text']}".encode("utf-8")`
 */
export function createSignedExportRecord(
  signer: TechnocoreSigner,
  room: string,
  seq: number,
  text: string,
  nonce: number,
  ts = new Date().toISOString(),
): string {
  const canonical = `${room}|${nonce}|${text}`;
  const payload = new TextEncoder().encode(canonical);
  const sigBytes = ed25519.sign(payload, signer.privateKey);
  const sig = base64urlnopad.encode(sigBytes);
  return (
    JSON.stringify({
      seq,
      ts,
      from: signer.did,
      text,
      nonce,
      sig,
    }) + "\n"
  );
}

/**
 * Verifies the Ed25519 DID signature on a raw exported Technocore message record.
 * Supports both TC Ledger canonical format `${room}|${nonce}|${text}` and
 * Technocore store format `${cleaned_text}:${seq}:${ts}`.
 */
export function verifyRecordSignature(rawRecordStr: string, room?: string): boolean {
  try {
    const record = JSON.parse(rawRecordStr);
    if (!record.from || !record.sig || !record.text || typeof record.seq !== "number") {
      return false;
    }
    const fromDid: string = record.from;
    if (!fromDid.startsWith("did:key:z6Mk")) {
      return false;
    }

    // Decode public key from did:key (strip 'did:key:z')
    const b58Str = fromDid.slice(9);
    const pubKeyBytes = base58.decode(b58Str);
    if (pubKeyBytes.length !== 34 || pubKeyBytes[0] !== 0xed || pubKeyBytes[1] !== 0x01) {
      return false;
    }
    const rawPubKey = pubKeyBytes.subarray(2);

    // Decode signature: 86-char base64urlnopad (or with padding)
    const normalizedSig = record.sig.replace(/=+$/, "");
    const sigBytes = base64urlnopad.decode(normalizedSig);
    if (sigBytes.length !== 64) {
      return false;
    }

    // 1. TC Ledger room-export signature: `${room}|${nonce}|${text}`
    if (record.nonce !== undefined && room) {
      const canonical = `${room}|${record.nonce}|${record.text}`;
      const payload = new TextEncoder().encode(canonical);
      if (ed25519.verify(sigBytes, payload, rawPubKey)) {
        return true;
      }
    }

    // 2. Technocore store/server signature: `${cleaned_text}:${seq}:${ts}`
    if (record.ts !== undefined) {
      const cleaned = sweptText(record.text);
      const signPayload = new TextEncoder().encode(`${cleaned}:${record.seq}:${record.ts}`);
      if (ed25519.verify(sigBytes, signPayload, rawPubKey)) {
        return true;
      }
    }

    return false;
  } catch {
    return false;
  }
}

// -----------------------------------------------------------------------------
// Subprocess CLI Wrappers for tc-ledger
// -----------------------------------------------------------------------------

export class TcLedgerCli {
  private readonly pythonPath: string;
  private readonly repoRoot: string;

  constructor(pythonPath = "python", repoRoot?: string) {
    this.pythonPath = pythonPath;
    this.repoRoot = repoRoot ?? path.resolve(process.cwd(), "..");
  }

  private getEnv(): NodeJS.ProcessEnv {
    const srcDir = path.resolve(this.repoRoot, "src");
    const existing = process.env.PYTHONPATH;
    const pythonPath = existing ? `${srcDir}${path.delimiter}${existing}` : srcDir;
    return {
      ...process.env,
      PYTHONPATH: pythonPath,
    };
  }

  /**
   * Runs `python -m tc_ledger.ledger commit <exportPath> --room <room> --output <outputPath>`
   */
  async commitExport(exportPath: string, room: string, outputPath?: string): Promise<TcExportCommitment> {
    const tempOut = outputPath ?? path.join(os.tmpdir(), `commit-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
    const args = ["-m", "tc_ledger.ledger", "commit", exportPath, "--room", room, "--output", tempOut];

    try {
      await execFileAsync(this.pythonPath, args, { cwd: this.repoRoot, env: this.getEnv() });
      const rawJson = fs.readFileSync(tempOut, "utf8");
      return JSON.parse(rawJson) as TcExportCommitment;
    } finally {
      if (!outputPath && fs.existsSync(tempOut)) {
        fs.unlinkSync(tempOut);
      }
    }
  }

  /**
   * Runs `python -m tc_ledger.ledger prove <exportPath> --room <room> --leaf-index <leafIndex> --output <outputPath>`
   */
  async proveLeaf(exportPath: string, room: string, leafIndex: number, outputPath?: string): Promise<TcInclusionProof> {
    const tempOut = outputPath ?? path.join(os.tmpdir(), `proof-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
    const args = ["-m", "tc_ledger.ledger", "prove", exportPath, "--room", room, "--leaf-index", leafIndex.toString(), "--output", tempOut];

    try {
      await execFileAsync(this.pythonPath, args, { cwd: this.repoRoot, env: this.getEnv() });
      const rawJson = fs.readFileSync(tempOut, "utf8");
      return JSON.parse(rawJson) as TcInclusionProof;
    } finally {
      if (!outputPath && fs.existsSync(tempOut)) {
        fs.unlinkSync(tempOut);
      }
    }
  }

  /**
   * Runs `python -m tc_ledger.ledger verify-proof <proofPath> --record <recordBinPath> --expected-root <root> --expected-room <room>`
   */
  async verifyProofCli(proofPath: string, recordBinPath: string, expectedRoot: string, expectedRoom: string): Promise<boolean> {
    const args = [
      "-m",
      "tc_ledger.ledger",
      "verify-proof",
      proofPath,
      "--record",
      recordBinPath,
      "--expected-root",
      expectedRoot,
      "--expected-room",
      expectedRoom,
    ];

    try {
      const { stdout } = await execFileAsync(this.pythonPath, args, { cwd: this.repoRoot, env: this.getEnv() });
      return stdout.includes("VERIFY-PROOF: VALID");
    } catch {
      return false;
    }
  }
}

// -----------------------------------------------------------------------------
// Archiver Integration Layer
// -----------------------------------------------------------------------------

export class TcLedgerArchiver {
  private readonly cli: TcLedgerCli;

  constructor(pythonPath = "python", repoRoot?: string) {
    this.cli = new TcLedgerCli(pythonPath, repoRoot);
  }

  /**
   * Archives a deal from an exact Technocore room export JSONL file.
   *
   * 1. Validates terminal deal status (unless allowIncomplete: true).
   * 2. Reads exact bytes of export file without reserialization.
   * 3. Invokes TC Ledger commit to obtain export commitment & root.
   * 4. Locates exact records by sequence number and generates inclusion proofs.
   * 5. Attaches evidence to DealManager.
   * 6. Builds a self-contained DealArchive artifact (without secrets!).
   */
  async archiveDeal(
    deal: DealManager,
    exportPath: string,
    options: ArchiveOptions = {},
  ): Promise<DealArchive> {
    if (!deal.isTerminal() && !options.allowIncomplete) {
      throw new DealArchivalError(
        `cannot archive non-terminal deal (status: ${deal.state.status}) without allowIncomplete flag`,
      );
    }

    if (!fs.existsSync(exportPath)) {
      throw new DealArchivalError(`export file not found: ${exportPath}`);
    }

    const exportBytes = fs.readFileSync(exportPath);
    const rawLines = sliceRawExportLines(exportBytes);
    const room = deal.state.room;

    // 1. Generate or verify Commitment via existing TC Ledger
    const commitment = await this.cli.commitExport(exportPath, room);
    if (commitment.verification.INVALID > 0 || commitment.verification.MALFORMED > 0) {
      throw new DealArchivalError(
        `room export contains invalid or malformed records (invalid: ${commitment.verification.INVALID}, malformed: ${commitment.verification.MALFORMED})`,
      );
    }

    // 2. Map sequence numbers to exact lines and generate inclusion proofs
    const recordSequences = deal.state.ledgerEvidence.recordSequences;
    const stageRecords: Record<string, ArchivedDealStageRecord> = {};
    const proofsByStage: Record<string, Record<string, unknown>> = {};

    for (const [stageKey, targetSeq] of Object.entries(recordSequences)) {
      if (typeof targetSeq !== "number") continue;
      const stageName = stageKey.replace(/Seq$/, "");

      // Find line with parsed.seq === targetSeq
      let matchedIndex = -1;
      let matchedLine: { buffer: Buffer; str: string } | null = null;

      for (let i = 0; i < rawLines.length; i++) {
        try {
          const parsed = JSON.parse(rawLines[i].str);
          if (parsed.seq === targetSeq) {
            matchedIndex = i;
            matchedLine = rawLines[i];
            break;
          }
        } catch {
          // ignore unparseable line during sequence scan
        }
      }

      if (matchedIndex === -1 || !matchedLine) {
        throw new DealArchivalError(
          `stage ${stageName} (seq: ${targetSeq}) not found in room export ${exportPath}`,
        );
      }

      // Compute leaf hash and obtain inclusion proof via CLI
      const leafHash = computeLeafHash(matchedLine.buffer);
      const proof = await this.cli.proveLeaf(exportPath, room, matchedIndex);

      if (proof.leaf_hash.toLowerCase() !== leafHash.toLowerCase()) {
        throw new DealArchivalError(
          `leaf hash mismatch for stage ${stageName}: proof has ${proof.leaf_hash}, calculated ${leafHash}`,
        );
      }

      stageRecords[stageName] = {
        stage: stageName,
        seq: targetSeq,
        leafIndex: matchedIndex,
        rawLine: matchedLine.str,
        leafHash,
        proof,
      };

      proofsByStage[stageName] = proof as unknown as Record<string, unknown>;
    }

    // 3. Attach evidence to DealManager
    const firstProof = Object.values(proofsByStage)[0];
    deal.attachLedgerCommitment(
      commitment.export_root,
      firstProof,
      proofsByStage,
      commitment as unknown as Record<string, unknown>,
    );

    // 4. Construct self-contained DealArchive
    // IMPORTANT: Strictly omit any plaintext secrets or private keys
    const dealRecord: DealRecord = deal.state;
    const archive: DealArchive = {
      schema: "technocore/deal-archive/v1",
      version: 1,
      archivedAtMs: Date.now(),
      deal: {
        contractId: dealRecord.contractId,
        room: dealRecord.room,
        status: dealRecord.status,
        payer: {
          did: dealRecord.payer.did,
          evmAddress: dealRecord.payer.evmAddress,
        },
        payee: {
          did: dealRecord.payee.did,
          evmAddress: dealRecord.payee.evmAddress,
        },
        terms: dealRecord.terms as Record<string, unknown> | undefined,
        rail: dealRecord.rail,
        ref: options.settlementRef ?? dealRecord.ref,
        createdAtMs: dealRecord.createdAtMs,
        updatedAtMs: dealRecord.updatedAtMs,
      },
      commitment,
      records: stageRecords,
      settlementEvidence: {
        settlementRail: dealRecord.rail,
        settlementRef: options.settlementRef ?? dealRecord.ref,
        onChainVerified: options.onChainVerified ?? false,
        disclaimer:
          "TC Ledger proves authenticity and room inclusion of signed Technocore messages under the export Merkle root. On-chain settlement execution must be independently verified via the EVM blockchain.",
      },
      verificationSummary: {
        verifiedOffline: true,
        trustModel: {
          provesRoomInclusion: true,
          provesSenderAuthenticity: true,
          provesOnChainSettlement: false,
          notice:
            "This archive provides cryptographic proof of message inclusion in the Technocore room export. It does not independently prove blockchain state.",
        },
      },
    };

    return archive;
  }
}

// -----------------------------------------------------------------------------
// Standalone Offline Verification Function
// -----------------------------------------------------------------------------

/**
 * Verifies a DealArchive offline without contacting technocore.chat.
 *
 * Verifies:
 * 1. Schema & structure.
 * 2. Commitment structure & root.
 * 3. Exact record bytes for each stage.
 * 4. Ed25519 signature authenticity of each record.
 * 5. Inclusion proof audit path leading to the committed Merkle root.
 * 6. Optional CLI double-verification using `tc-ledger verify-proof`.
 */
export async function verifyDealArchive(
  archive: DealArchive,
  options: { pythonPath?: string; useCli?: boolean; repoRoot?: string } = {},
): Promise<VerificationResult> {
  const errors: string[] = [];
  const stagesVerified: string[] = [];

  if (archive.schema !== "technocore/deal-archive/v1" || archive.version !== 1) {
    errors.push(`invalid archive schema or version: ${archive.schema} v${archive.version}`);
    return { valid: false, errors, stagesVerified };
  }

  const { commitment, records, deal } = archive;
  if (!commitment || !commitment.export_root) {
    errors.push("missing commitment or export_root in archive");
    return { valid: false, errors, stagesVerified };
  }

  if (commitment.room !== deal.room) {
    errors.push(`commitment room mismatch: expected ${deal.room}, got ${commitment.room}`);
  }

  // Verify each stage record
  for (const [stageName, stageData] of Object.entries(records)) {
    // A. Check raw line bytes and leaf hash
    const rawBytes = Buffer.from(stageData.rawLine, "utf8");
    const computedLeafHash = computeLeafHash(rawBytes);
    if (computedLeafHash.toLowerCase() !== stageData.leafHash.toLowerCase()) {
      errors.push(
        `stage '${stageName}': leaf hash mismatch. Computed ${computedLeafHash}, archive has ${stageData.leafHash}`,
      );
      continue;
    }

    // B. Check Ed25519 record signature authenticity
    const sigValid = verifyRecordSignature(stageData.rawLine, deal.room);
    if (!sigValid) {
      errors.push(`stage '${stageName}': Technocore DID signature verification failed`);
      continue;
    }

    // C. Check inclusion proof audit path
    const proofValid = verifyInclusionProofInMemory(
      stageData.proof,
      rawBytes,
      commitment.export_root,
      deal.room,
    );
    if (!proofValid) {
      errors.push(`stage '${stageName}': inclusion proof Merkle verification failed`);
      continue;
    }

    // D. Optional CLI verification via `python -m tc_ledger.ledger verify-proof`
    if (options.useCli) {
      const cli = new TcLedgerCli(options.pythonPath ?? "python", options.repoRoot);
      const tempProof = path.join(os.tmpdir(), `vproof-${Date.now()}-${stageName}.json`);
      const tempRec = path.join(os.tmpdir(), `vrec-${Date.now()}-${stageName}.bin`);

      try {
        fs.writeFileSync(tempProof, JSON.stringify(stageData.proof, null, 2), "utf8");
        fs.writeFileSync(tempRec, rawBytes);
        const cliOk = await cli.verifyProofCli(
          tempProof,
          tempRec,
          commitment.export_root,
          deal.room,
        );
        if (!cliOk) {
          errors.push(`stage '${stageName}': tc-ledger CLI verify-proof failed`);
          continue;
        }
      } catch (err) {
        errors.push(`stage '${stageName}': CLI verification error: ${(err as Error).message}`);
        continue;
      } finally {
        if (fs.existsSync(tempProof)) fs.unlinkSync(tempProof);
        if (fs.existsSync(tempRec)) fs.unlinkSync(tempRec);
      }
    }

    stagesVerified.push(stageName);
  }

  return {
    valid: errors.length === 0 && stagesVerified.length > 0,
    errors,
    stagesVerified,
  };
}
