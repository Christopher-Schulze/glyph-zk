#!/usr/bin/env node
import fs from "fs";
import { TurboFactory } from "@ardrive/turbo-sdk";

const payloadPath = process.env.ARWEAVE_DATA_PATH;
const jwkPath = process.env.ARWEAVE_JWK_PATH;
const gatewayUrl = process.env.ARWEAVE_GATEWAY_URL || "https://arweave.net";

if (!payloadPath) {
  console.error("ERROR: ARWEAVE_DATA_PATH not set");
  process.exit(1);
}
if (!jwkPath) {
  console.error("ERROR: ARWEAVE_JWK_PATH not set");
  process.exit(1);
}

const jwkRaw = fs.readFileSync(jwkPath, "utf8");
const privateKey = JSON.parse(jwkRaw);

const turbo = TurboFactory.authenticated({ privateKey });

const fileStreamFactory = () => fs.createReadStream(payloadPath);
const fileSizeFactory = () => fs.statSync(payloadPath).size;
const result = await turbo.uploadFile({ fileStreamFactory, fileSizeFactory });

const txId =
  result?.id ||
  result?.dataItemId ||
  result?.transactionId ||
  result?.data?.id ||
  "";

if (!txId) {
  console.error("ERROR: Turbo upload returned no tx id");
  process.exit(1);
}

const out = { tx_id: txId, gateway_url: gatewayUrl };
console.log(JSON.stringify(out));
