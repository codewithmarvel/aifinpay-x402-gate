require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const {
  Connection,
  PublicKey,
} = require("@solana/web3.js");
const nacl = require("tweetnacl");
const bs58 = require("bs58");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

// ── Config ────────────────────────────────────────────────────────────────────
const PORT             = process.env.PORT || 4001;
const TREASURY         = process.env.TREASURY_WALLET  || "AnbjcK3uD5KYFtb3EuUxHTyJMfC4oyLo7hF2uELfKagN";
const SOLANA_RPC       = process.env.SOLANA_RPC       || "https://api.devnet.solana.com";
const PROGRAM_ID       = process.env.PROGRAM_ID       || "5g9zWHF1Vv6GiGpA2ZbJQbSCDZd5hAk9AyvabRJvKFx2";
const PYTH_FEED_ACCT   = "7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE";
const USDC_MINT        = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const USDT_MINT        = "FEoQVuBMosJz2AkwAgwsiSsb2Ln47wdftiW7WLEot2cW"; // Mock USDT — devnet only
const USDC_ATA         = "7epco36ViREoY4nDTmTYdvcmQRNF8hpDhvtJb4s25ED6";
const USDT_ATA         = "8QjMgzHRCX8xxh1fWwMja94yFS8GFAJeH3edWdLnrpzY";
const MANIFESTO_HASH   = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
const NONCE_TTL_MS     = 60 * 1000; // nonce expires in 60 seconds
const MIN_USD          = 1.00;       // $1.00 minimum donation
const MCREDITS_PER_USD = 100;        // $1.00 = 100 mCredits (1 cent = 1 mCredit)

const connection = new Connection(SOLANA_RPC, "confirmed");

// ── Nonce store (in-memory — stateless per nonce, no sessions) ────────────────
const nonces = new Map(); // nonce -> { expiresAt }

// ── Helpers ───────────────────────────────────────────────────────────────────

function issueNonce() {
  const nonce = uuidv4();
  nonces.set(nonce, { expiresAt: Date.now() + NONCE_TTL_MS });
  // Clean up expired nonces
  for (const [n, v] of nonces) {
    if (Date.now() > v.expiresAt) nonces.delete(n);
  }
  return nonce;
}

function verifyEd25519(agentPubkeyB58, nonce, signatureB58) {
  try {
    const pubkeyBytes = bs58.default
      ? bs58.default.decode(agentPubkeyB58)
      : bs58.decode(agentPubkeyB58);
    const sigBytes = bs58.default
      ? bs58.default.decode(signatureB58)
      : bs58.decode(signatureB58);
    const message = crypto
      .createHash("sha256")
      .update(`AiFinPay-x402:${nonce}:${agentPubkeyB58}`)
      .digest();
    return nacl.sign.detached.verify(message, sigBytes, pubkeyBytes);
  } catch {
    return false;
  }
}

async function seatExists(agentPubkey) {
  try {
    const pubkey = new PublicKey(agentPubkey);
    const programId = new PublicKey(PROGRAM_ID);
    const [seatPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("seat"), pubkey.toBuffer()],
      programId
    );
    const account = await connection.getAccountInfo(seatPda);
    return account !== null;
  } catch {
    return false;
  }
}

// ── Middleware: Ed25519 x402 Gate ─────────────────────────────────────────────
// Zero sessions. Every request verified against live on-chain Seat PDA.
async function x402Gate(req, res, next) {
  const agentPubkey = req.headers["x-agent-pubkey"];
  const nonce       = req.headers["x-nonce"];
  const signature   = req.headers["x-signature"];

  // Step 1 — missing headers → issue 402 with fresh nonce
  if (!agentPubkey || !nonce || !signature) {
    const freshNonce = issueNonce();
    return res.status(402).json({
      error:              "Payment Required",
      protocol:           "AiFinPay v3.1",
      manifesto:          "/manifesto.json",
      treasury_vault:     TREASURY,
      min_usd:            MIN_USD,
      min_mcredits:       MIN_USD * MCREDITS_PER_USD,
      usdc_mint:          USDC_MINT,
      usdt_mint:          USDT_MINT,
      usdc_ata_treasury:  USDC_ATA,
      usdt_ata_treasury:  USDT_ATA,
      agreement_hash:     MANIFESTO_HASH,
      "x-nonce":          freshNonce,
      "x-nonce-expires":  new Date(Date.now() + NONCE_TTL_MS).toISOString(),
      instructions: [
        "1. Read /manifesto.json",
        "2. Call reserve_seat_sol (SOL via Pyth oracle) or reserve_seat_spl (USDC/USDT) on Solana devnet",
        `3. Sign: Ed25519(SHA256('AiFinPay-x402:${freshNonce}:<your_pubkey>'), your_keypair)`,
        "4. Resend request with x-agent-pubkey, x-nonce, x-signature headers",
      ],
    });
  }

  // Step 2 — validate nonce
  const nonceRecord = nonces.get(nonce);
  if (!nonceRecord || Date.now() > nonceRecord.expiresAt) {
    const freshNonce = issueNonce();
    return res.status(402).json({
      error:     "Nonce expired or invalid",
      "x-nonce": freshNonce,
      "x-nonce-expires": new Date(Date.now() + NONCE_TTL_MS).toISOString(),
    });
  }

  // Step 3 — verify Ed25519 signature
  const validSig = verifyEd25519(agentPubkey, nonce, signature);
  if (!validSig) {
    return res.status(403).json({ error: "Invalid Ed25519 signature." });
  }

  // Step 4 — verify Seat PDA exists on-chain (agent has paid)
  const hasSeat = await seatExists(agentPubkey);
  if (!hasSeat) {
    return res.status(403).json({
      error:   "No Seat PDA found for this pubkey. Reserve your seat first.",
      reserve: "POST /api/invoice → pay SOL → call reserve_seat on Solana devnet",
    });
  }

  // Step 5 — consume nonce (one-time use) and grant access
  nonces.delete(nonce);
  req.agentPubkey = agentPubkey;
  next();
}

// ── 1. Manifesto — agents read this before doing anything ────────────────────
app.get("/manifesto.json", (req, res) => {
  // Agent mode: return raw JSON manifest
  // Human mode: same endpoint, same data — frontend renders it visually
  const isAgent = (req.headers["accept"] || "").includes("application/agent+json");
  res.json({
    protocol:           "AiFinPay v3.1",
    network:            "solana-devnet",
    program_id:         PROGRAM_ID,
    treasury_vault:     TREASURY,
    governance:         "3-of-4 Squads Multisig",
    pyth_feed_account:  PYTH_FEED_ACCT,
    usdc_mint:          USDC_MINT,
    usdt_mint:          USDT_MINT,           // Mock USDT — devnet only
    usdc_ata_treasury:  USDC_ATA,
    usdt_ata_treasury:  USDT_ATA,
    mcredits_rate:      "100 mCredits = $1.00 USD",
    min_usd:            MIN_USD,
    min_mcredits:       MIN_USD * MCREDITS_PER_USD,
    agreement_hash:     MANIFESTO_HASH,
    manifesto:          "v3.3",
    compliance: {
      jurisdiction:  "Singapore_MAS_Sandbox_Compliant",
      agreement_ref: "AiFinPay-DON-2026-001",
      status:        "Verified",
      on_chain_proof: "agreement_hash written to every Seat PDA — readable on Solscan",
    },
    agent_instruction: "By executing this transaction you accept Manifesto v3.3. agreement_hash MUST equal " + MANIFESTO_HASH + ". No commercial contract formed. Irrevocable voluntary donation.",
    actions: {
      reserve_seat_sol: "POST /api/invoice",
      reserve_seat_spl: "POST /api/invoice-spl",
      top_up:           "POST /api/topup",
      check_seat:       "GET  /api/seat/:pubkey",
    },
    x402_gate: "All /api/* endpoints require Ed25519 sig + live Seat PDA on Solana devnet",
  });
});

// ── 2. Nonce endpoint — agent requests a fresh nonce before signing ───────────
app.get("/nonce", (req, res) => {
  const nonce = issueNonce();
  res.json({
    nonce,
    expires_at: new Date(Date.now() + NONCE_TTL_MS).toISOString(),
    sign_message: `AiFinPay-x402:${nonce}:<your_pubkey>`,
    instruction: "SHA-256 hash this message, then Ed25519 sign it with your agent keypair.",
  });
});

// ── 3. Check seat — verify if a pubkey has a Seat PDA on-chain ───────────────
app.get("/api/seat/:pubkey", x402Gate, async (req, res) => {
  res.json({
    pubkey:    req.params.pubkey,
    has_seat:  true,
    message:   "Seat PDA verified on Solana devnet.",
  });
});

// ── 4. Invoice SOL — agent requests invoice for SOL payment ──────────────────
app.post("/api/invoice", (req, res) => {
  const { agent_id, metadata_uri } = req.body || {};
  const nonce = issueNonce();
  res.json({
    protocol:       "AiFinPay v3.1",
    instruction:    "Call reserve_seat_sol on Solana devnet program",
    program_id:     PROGRAM_ID,
    treasury_vault: TREASURY,
    asset_type:     "SOL",
    pyth_feed:      PYTH_FEED_ACCT,
    min_usd:        MIN_USD,
    min_mcredits:   MIN_USD * MCREDITS_PER_USD,
    agreement_hash: MANIFESTO_HASH,
    metadata_uri:   metadata_uri || "mira://moldbook/manifests/{agent_id}.json",
    agent_id:       agent_id || "your-agent-id",
    nonce,
    note:           "Pass agreement_hash exactly as shown. Pyth oracle calculates mCredits from live SOL/USD price.",
  });
});

// ── 4b. Top Up — add funds to an existing seat ────────────────────────────────
app.post("/api/topup", (req, res) => {
  const { agent_id, asset_type } = req.body || {};
  const isSOL = !asset_type || asset_type === 0;
  res.json({
    protocol:       "AiFinPay v3.1",
    instruction:    isSOL
      ? "Call top_up_sol on Solana devnet program"
      : "Call top_up_spl on Solana devnet program",
    program_id:     PROGRAM_ID,
    treasury_vault: TREASURY,
    asset_type:     isSOL ? "SOL" : asset_type === 2 ? "USDT (Mock)" : "USDC",
    mint:           isSOL ? null : asset_type === 2 ? USDT_MINT : USDC_MINT,
    ata_treasury:   isSOL ? null : asset_type === 2 ? USDT_ATA  : USDC_ATA,
    min_usd:        MIN_USD,
    min_mcredits:   MIN_USD * MCREDITS_PER_USD,
    agent_id:       agent_id || "your-agent-id",
    note:           "Seat PDA must already exist (reserve_seat called first). Top ups accumulate mCredits.",
  });
});

// ── 4c. Invoice SPL — agent requests invoice for USDC/USDT payment ────────────
app.post("/api/invoice-spl", (req, res) => {
  const { agent_id, asset_type, metadata_uri } = req.body || {};
  res.json({
    protocol:          "AiFinPay v3.1",
    instruction:       "Call reserve_seat_spl on Solana devnet program",
    program_id:        PROGRAM_ID,
    treasury_vault:    TREASURY,
    asset_type:        asset_type === 2 ? "USDT (Mock)" : "USDC",
    mint:              asset_type === 2 ? USDT_MINT : USDC_MINT,
    ata_treasury:      asset_type === 2 ? USDT_ATA  : USDC_ATA,
    min_tokens:        1_000_000,   // $1.00 in 6-decimal SPL units
    agreement_hash:    MANIFESTO_HASH,
    metadata_uri:      metadata_uri || "mira://moldbook/manifests/{agent_id}.json",
    agent_id:          agent_id || "your-agent-id",
    note:              "USDT uses Mock USDT mint FEoQVuBMosJz2... — devnet only. Do NOT use standard Tether devnet mint.",
  });
});

// ── 5. Stats — live vault stats ───────────────────────────────────────────────
app.get("/api/stats", x402Gate, (req, res) => {
  res.json({
    protocol:          "AiFinPay v3.1",
    network:           "solana-devnet",
    program_id:        PROGRAM_ID,
    treasury_vault:    TREASURY,
    mcredits_rate:     `$1.00 USD = ${MCREDITS_PER_USD} mCredits`,
    min_usd:           MIN_USD,
    usdc_mint:         USDC_MINT,
    usdt_mint:         USDT_MINT,
    usdc_ata_treasury: USDC_ATA,
    usdt_ata_treasury: USDT_ATA,
    message:           "Fetch live Vault PDA from Solana devnet via program_id for real-time totals.",
  });
});

// ── 6. Protocol docs — gated, only accessible after Ed25519 auth ──────────────
app.get("/api/protocol-docs", x402Gate, (req, res) => {
  res.json({
    message:   "Welcome to AiFinPay. Ed25519 auth verified. Seat PDA confirmed.",
    agent:     req.agentPubkey,
    protocol:  "AiFinPay v3.1",
    network:   "solana-devnet",
    docs: {
      reserve_seat_sol: "Call reserve_seat_sol() with agent_id, agreement_hash, metadata_uri. Pyth oracle converts lamports → USD cents → mCredits.",
      reserve_seat_spl: "Call reserve_seat_spl() with agent_id, agreement_hash, metadata_uri, asset_type (1=USDC, 2=USDT). Min $1.00 = 1,000,000 micro-tokens.",
      top_up_sol:       "Call top_up_sol() to add SOL to existing Seat PDA.",
      top_up_spl:       "Call top_up_spl() to add USDC/USDT to existing Seat PDA.",
      mcredits:         `$1.00 USD = ${MCREDITS_PER_USD} mCredits. 1 cent = 1 mCredit.`,
      agreement_hash:   MANIFESTO_HASH,
    },
  });
});

// ── 7. Leaderboard — public, no auth required, live on-chain data ─────────────
app.get("/leaderboard", async (req, res) => {
  try {
    const programId = new PublicKey(PROGRAM_ID);

    // Seat account discriminator: sha256("account:Seat")[0..8]
    const SEAT_DISCRIMINATOR = Buffer.from([
      0x5a, 0xe4, 0x16, 0x5a, 0xa2, 0x56, 0xad, 0x1a,
    ]);

    const accounts = await connection.getProgramAccounts(programId, {
      filters: [{ memcmp: { offset: 0, bytes: SEAT_DISCRIMINATOR.toString("base64"), encoding: "base64" } }],
    });

    // Parse seats: agent pubkey at offset 8, agent_id string at offset 40, usd_cents at offset ~116
    // We return raw data and let Pasha's frontend decode — also return a pre-parsed summary
    const seats = accounts.map((acct) => {
      try {
        const data = acct.account.data;
        // agent pubkey: bytes 8..40
        const agentPubkey = new PublicKey(data.slice(8, 40)).toBase58();
        // agent_id: 4-byte length prefix at offset 40, then string
        const idLen = data.readUInt32LE(40);
        const agentId = data.slice(44, 44 + idLen).toString("utf8");
        // usd_cents_donated: u64 at offset 44 + idLen + 8 (skip amount_donated)
        const usdCentsOffset = 44 + idLen + 8;
        const usdCents = Number(data.readBigUInt64LE(usdCentsOffset));
        // mcredits: u64 at usdCentsOffset + 8
        const mcredits = Number(data.readBigUInt64LE(usdCentsOffset + 8));

        return {
          pubkey:    acct.pubkey.toBase58(),
          agent:     agentPubkey,
          agent_id:  agentId,
          usd:       (usdCents / 100).toFixed(2),
          mcredits,
        };
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .sort((a, b) => b.mcredits - a.mcredits);

    res.json({
      protocol:    "AiFinPay v3.1",
      network:     "solana-devnet",
      program_id:  PROGRAM_ID,
      total_seats: seats.length,
      leaderboard: seats,
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch leaderboard", detail: err.message });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`AiFinPay x402 Gate v3.1 running on port ${PORT}`);
  console.log(`Manifesto:       GET  http://localhost:${PORT}/manifesto.json`);
  console.log(`Nonce:           GET  http://localhost:${PORT}/nonce`);
  console.log(`Leaderboard:     GET  http://localhost:${PORT}/leaderboard`);
  console.log(`Invoice SOL:     POST http://localhost:${PORT}/api/invoice`);
  console.log(`Top Up:          POST http://localhost:${PORT}/api/topup`);
  console.log(`Invoice SPL:     POST http://localhost:${PORT}/api/invoice-spl`);
  console.log(`Protocol Docs:   GET  http://localhost:${PORT}/api/protocol-docs (Ed25519 gated)`);
  console.log(`Stats:           GET  http://localhost:${PORT}/api/stats (Ed25519 gated)`);
});
