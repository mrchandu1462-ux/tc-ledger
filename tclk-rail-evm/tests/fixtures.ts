// SPDX-License-Identifier: Apache-2.0

import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import { readFileSync } from "node:fs";
import {
  createPublicClient,
  createWalletClient,
  http,
  type PublicClient,
  type WalletClient,
  type Address,
  type Hash,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { HTLC_ABI, ERC20_ABI } from "../src/abi.js";

const htlcArtifact = JSON.parse(
  readFileSync(new URL("../out/Htlc.sol/Htlc.json", import.meta.url), "utf8"),
);
const erc20Artifact = JSON.parse(
  readFileSync(new URL("../out/MockERC20.sol/MockERC20.json", import.meta.url), "utf8"),
);

export const ANVIL_PATH = process.env.ANVIL_PATH ?? "anvil";

// Default pre-funded Anvil accounts
export const PAYER_PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
export const PAYEE_PRIVATE_KEY =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as const;
export const STRANGER_PRIVATE_KEY =
  "0x5de4111afa1a4b93908f11f6bdd09feac5f22a21e50915a4f0e137a867ac860f" as const;

export const payerAccount = privateKeyToAccount(PAYER_PRIVATE_KEY);
export const payeeAccount = privateKeyToAccount(PAYEE_PRIVATE_KEY);
export const strangerAccount = privateKeyToAccount(STRANGER_PRIVATE_KEY);

export interface AnvilContext {
  port: number;
  process: ChildProcess;
  publicClient: PublicClient;
  payerWallet: WalletClient;
  payeeWallet: WalletClient;
  strangerWallet: WalletClient;
  htlcAddress: Address;
  tokenAddress: Address;
  setNextBlockTimestamp: (timestamp: bigint) => Promise<void>;
  mineBlock: () => Promise<void>;
  getBlockTimestamp: () => Promise<bigint>;
  stop: () => Promise<void>;
}

async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, () => {
      const port = (srv.address() as { port: number }).port;
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

export async function startAnvil(): Promise<AnvilContext> {
  const port = await getFreePort();
  const child = spawn(ANVIL_PATH, ["--port", String(port), "--silent"], {
    stdio: "ignore",
    windowsHide: true,
  });

  const rpcUrl = `http://127.0.0.1:${port}`;

  // Poll until RPC is responding
  let ready = false;
  for (let i = 0; i < 50; i++) {
    try {
      const res = await fetch(rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "net_version", params: [] }),
      });
      if (res.ok) {
        ready = true;
        break;
      }
    } catch {
      await new Promise((r) => setTimeout(r, 100));
    }
  }

  if (!ready) {
    child.kill();
    throw new Error(`Failed to start Anvil on port ${port}`);
  }

  const transport = http(rpcUrl);

  const publicClient = createPublicClient({
    chain: foundry,
    transport,
  });

  const payerWallet = createWalletClient({
    account: payerAccount,
    chain: foundry,
    transport,
  });

  const payeeWallet = createWalletClient({
    account: payeeAccount,
    chain: foundry,
    transport,
  });

  const strangerWallet = createWalletClient({
    account: strangerAccount,
    chain: foundry,
    transport,
  });

  // Deploy Htlc
  const htlcDeployHash = await payerWallet.deployContract({
    abi: HTLC_ABI,
    bytecode: htlcArtifact.bytecode.object as Hash,
  });
  const htlcReceipt = await publicClient.waitForTransactionReceipt({ hash: htlcDeployHash });
  const htlcAddress = htlcReceipt.contractAddress!;

  // Deploy MockERC20
  const erc20DeployHash = await payerWallet.deployContract({
    abi: ERC20_ABI,
    bytecode: erc20Artifact.bytecode.object as Hash,
    args: ["Test USDC", "USDC"],
  });
  const erc20Receipt = await publicClient.waitForTransactionReceipt({ hash: erc20DeployHash });
  const tokenAddress = erc20Receipt.contractAddress!;

  // Mint tokens to payer
  const mintHash = await payerWallet.writeContract({
    address: tokenAddress,
    abi: ERC20_ABI,
    functionName: "mint",
    args: [payerAccount.address, 1000000000000000000000000n],
    account: payerAccount,
    chain: foundry,
  });
  await publicClient.waitForTransactionReceipt({ hash: mintHash });

  const setNextBlockTimestamp = async (timestamp: bigint) => {
    await publicClient.request({
      method: "evm_setNextBlockTimestamp" as any,
      params: [Number(timestamp)] as any,
    });
  };

  const mineBlock = async () => {
    await publicClient.request({
      method: "evm_mine" as any,
      params: [] as any,
    });
  };

  const getBlockTimestamp = async () => {
    const block = await publicClient.getBlock();
    return block.timestamp;
  };

  const stop = async () => {
    child.kill();
  };

  return {
    port,
    process: child,
    publicClient,
    payerWallet,
    payeeWallet,
    strangerWallet,
    htlcAddress,
    tokenAddress,
    setNextBlockTimestamp,
    mineBlock,
    getBlockTimestamp,
    stop,
  };
}
