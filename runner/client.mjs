import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { createReadStream } from 'node:fs';
import { chmod, mkdir, mkdtemp, open, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const API_ORIGIN = 'https://sign.voidcarve.com';
const MAX_JSON_BYTES = 1_000_000;
const ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NONCE_RE = /^[A-Za-z0-9_-]{43}$/;
const RUNNER_TOKEN_RE = /^vcr_[A-Za-z0-9_-]{43}$/;
const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;
const MIN_PART_BYTES = 5 * 1024 * 1024;
const MAX_PART_BYTES = 64 * 1024 * 1024;
const MAX_PARTS = 10_000;
const MAX_ATTEMPTS = 5;
const BACKOFF_MS = [2000, 4000, 8000, 16000];
const PART_TIMEOUT_MS = 300_000;
const ZIP = '/usr/bin/zip';
const SAFE_OUTPUTS = new Set(['signed.tar.gz', 'product.zip', 'signed.dmg', 'product.dmg']);

export class ClientError extends Error {
  constructor(code, status = 0) { super(code); this.code = code; this.status = status; }
}

const transientStatus = status => status >= 500 || status === 408 || status === 429;
const defaultSleep = ms => new Promise(resolve => setTimeout(resolve, ms));

export function validateInvocation(input) {
  if (!input || !ID_RE.test(input.requestId ?? '') || !/^[1-9]\d*$/.test(input.generation ?? '') || !NONCE_RE.test(input.nonce ?? '')) throw new ClientError('INVALID_INPUT');
  const generation = Number(input.generation);
  const runId = Number(input.runId);
  if (!Number.isSafeInteger(generation) || generation < 1 || !/^[1-9]\d*$/.test(String(input.runId ?? '')) || !Number.isSafeInteger(runId) || String(input.runAttempt) !== '1') throw new ClientError('INVALID_INPUT');
  if (input.visibility !== 'public' && input.visibility !== 'private') throw new ClientError('INVALID_INPUT');
  return { requestId: input.requestId, generation, nonce: input.nonce, visibility: input.visibility, runId, runAttempt: 1 };
}

export function validateRoute(action) {
  if (!['claim', 'heartbeat', 'download', 'authorize-sign', 'output', 'complete'].includes(action)) throw new ClientError('INVALID_ROUTE');
  return `${API_ORIGIN}/runner/v1/requests`;
}

async function parseJson(response) {
  const length = Number(response.headers.get('content-length') ?? 0);
  if (length > MAX_JSON_BYTES) throw new ClientError('INVALID_RESPONSE');
  if (!response.body) throw new ClientError('INVALID_RESPONSE');
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.byteLength;
    if (size > MAX_JSON_BYTES) throw new ClientError('INVALID_RESPONSE');
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks, size);
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new ClientError('INVALID_RESPONSE'); }
}

function validateActionResult(action, body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new ClientError('INVALID_RESPONSE');
  if (action === 'claim' && !body.manifest) throw new ClientError('INVALID_RESPONSE');
  if (action === 'output') {
    const parts = body.received_parts;
    if (!Number.isSafeInteger(body.part_size) || body.part_size < MIN_PART_BYTES || body.part_size > MAX_PART_BYTES
      || !Number.isSafeInteger(body.part_count) || body.part_count < 1 || body.part_count > MAX_PARTS
      || !Array.isArray(parts) || parts.some(part => !Number.isSafeInteger(part) || part < 1 || part > body.part_count)) throw new ClientError('INVALID_RESPONSE');
  }
  if (action === 'authorize-sign' && (typeof body.operation_id !== 'string' || !/^[A-Za-z0-9_:-]{16,128}$/.test(body.operation_id))) throw new ClientError('INVALID_RESPONSE');
  if (action === 'heartbeat' && (!Number.isSafeInteger(body.lease_until) || body.lease_until <= Date.now())) throw new ClientError('INVALID_RESPONSE');
  if (action === 'complete' && body.state !== 'verifying') throw new ClientError('INVALID_RESPONSE');
  return body;
}

async function apiFailure(response) {
  const detail = await parseJson(response).catch(() => null);
  return new ClientError(typeof detail?.error === 'string' && /^[a-z_]{1,64}$/.test(detail.error) ? `API_${detail.error.toUpperCase()}` : 'API_REQUEST_FAILED', response.status);
}

function identityHeaders(invocation, runnerToken) {
  return {
    authorization: `Bearer ${runnerToken}`,
    'x-signing-generation': String(invocation.generation),
    'x-signing-nonce': invocation.nonce,
    'x-signing-run-id': String(invocation.runId),
    'x-signing-run-attempt': String(invocation.runAttempt),
  };
}

export function createApi({ fetchImpl = fetch, runnerToken = process.env.SIGNING_RUNNER_TOKEN } = {}) {
  if (!RUNNER_TOKEN_RE.test(runnerToken ?? '')) throw new ClientError('RUNNER_TOKEN_UNAVAILABLE');
  return async (action, input, extra = {}) => {
    validateRoute(action);
    const invocation = validateInvocation(input);
    const url = `${API_ORIGIN}/runner/v1/requests/${encodeURIComponent(input.requestId)}/${action}`;
    const response = await fetchImpl(url, {
      method: 'POST', redirect: 'error',
      headers: { authorization: `Bearer ${runnerToken}`, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ ...extra, generation: invocation.generation, nonce: invocation.nonce, run_id: invocation.runId, run_attempt: invocation.runAttempt }),
    });
    if (action === 'complete') {
      if (response.status !== 202) throw await apiFailure(response);
    } else if (!response.ok) throw await apiFailure(response);
    return validateActionResult(action, await parseJson(response));
  };
}

function contentRangeStart(value) {
  const match = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(value ?? '');
  return match ? { start: Number(match[1]), total: Number(match[3]) } : null;
}

export async function downloadObject(invocation, object, destination, { digest, maxBytes, fetchImpl = fetch, runnerToken = process.env.SIGNING_RUNNER_TOKEN, sleep = defaultSleep }) {
  validateRoute('download');
  if (!RUNNER_TOKEN_RE.test(runnerToken ?? '')) throw new ClientError('RUNNER_TOKEN_UNAVAILABLE');
  if (object !== 'input' && object !== 'template') throw new ClientError('INVALID_INPUT');
  if (!DIGEST_RE.test(digest ?? '') || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 2_000_000_000) throw new ClientError('INVALID_DOWNLOAD_METADATA');
  const url = `${API_ORIGIN}/runner/v1/requests/${encodeURIComponent(invocation.requestId)}/download`;
  const body = JSON.stringify({ generation: invocation.generation, nonce: invocation.nonce, run_id: invocation.runId, run_attempt: invocation.runAttempt, object });
  const handle = await open(destination, 'wx', 0o600);
  let hasher = createHash('sha256');
  let written = 0;
  let total = 0;
  try {
    for (let attempt = 1; ; attempt += 1) {
      try {
        const headers = { authorization: `Bearer ${runnerToken}`, 'content-type': 'application/json' };
        if (written > 0) headers.range = `bytes=${written}-`;
        const response = await fetchImpl(url, { method: 'POST', redirect: 'error', headers, body });
        if (response.status >= 300 && response.status < 400) throw new ClientError('DOWNLOAD_FAILED');
        if (!response.ok) {
          if (transientStatus(response.status)) throw new Error('transient');
          throw await apiFailure(response);
        }
        if (!response.body) throw new Error('transient');
        const length = Number(response.headers.get('content-length') ?? NaN);
        if (response.status === 206) {
          const range = contentRangeStart(response.headers.get('content-range'));
          if (!range || range.start !== written || written === 0) throw new ClientError('DOWNLOAD_FAILED');
          total = range.total;
        } else if (response.status === 200) {
          if (!Number.isSafeInteger(length)) throw new ClientError('DOWNLOAD_FAILED');
          if (written > 0) { await handle.truncate(0); hasher = createHash('sha256'); written = 0; }
          total = length;
        } else throw new ClientError('DOWNLOAD_FAILED');
        if (total < 1 || total > maxBytes) throw new ClientError('DOWNLOAD_TOO_LARGE');
        for await (const chunk of response.body) {
          if (written + chunk.length > total) throw new ClientError('DOWNLOAD_TOO_LARGE');
          await handle.write(chunk, 0, chunk.length, written);
          hasher.update(chunk);
          written += chunk.length;
        }
        if (written !== total) throw new Error('transient');
        break;
      } catch (error) {
        if (error instanceof ClientError && !transientStatus(error.status)) throw error;
        if (attempt >= MAX_ATTEMPTS) throw new ClientError('DOWNLOAD_FAILED');
        await sleep(BACKOFF_MS[attempt - 1]);
      }
    }
  } catch (error) {
    await handle.close();
    await rm(destination, { force: true });
    throw error instanceof ClientError ? error : new ClientError('DOWNLOAD_FAILED');
  }
  await handle.close();
  if (`sha256:${hasher.digest('hex')}` !== digest) {
    await rm(destination, { force: true });
    throw new ClientError('DOWNLOAD_DIGEST_MISMATCH');
  }
  return { size: written };
}

export async function bundleOutput(outputDir, verification, work, maxBytes) {
  const bundle = path.join(work, 'output.zip');
  const payload = path.join(outputDir, verification.files[0].path);
  await execFileAsync(ZIP, ['-q', '-X', '-j', '-0', bundle, payload, path.join(outputDir, 'verification.json')]);
  const info = await stat(bundle);
  if (!info.isFile() || info.size < 1 || info.size > maxBytes) throw new ClientError('INVALID_OUTPUT');
  const hasher = createHash('sha256');
  for await (const chunk of createReadStream(bundle)) hasher.update(chunk);
  return { path: bundle, size: info.size, digest: `sha256:${hasher.digest('hex')}` };
}

async function putPart(invocation, bundle, part, partSize, { fetchImpl, runnerToken }) {
  const start = (part - 1) * partSize;
  const end = Math.min(bundle.size, start + partSize) - 1;
  const response = await fetchImpl(`${API_ORIGIN}/runner/v1/requests/${encodeURIComponent(invocation.requestId)}/output/parts/${part}`, {
    method: 'PUT', redirect: 'error', duplex: 'half', signal: AbortSignal.timeout(PART_TIMEOUT_MS),
    headers: { ...identityHeaders(invocation, runnerToken), 'content-type': 'application/octet-stream', 'content-length': String(end - start + 1) },
    body: createReadStream(bundle.path, { start, end }),
  });
  if (!response.ok) throw await apiFailure(response);
  await response.body?.cancel();
}

export async function uploadOutput(invocation, bundle, { api, fetchImpl = fetch, runnerToken = process.env.SIGNING_RUNNER_TOKEN, sleep = defaultSleep }) {
  if (!RUNNER_TOKEN_RE.test(runnerToken ?? '')) throw new ClientError('RUNNER_TOKEN_UNAVAILABLE');
  const begin = () => api('output', invocation, { archive_digest: bundle.digest, archive_size: bundle.size });
  let session = await begin();
  if (session.part_count !== Math.ceil(bundle.size / session.part_size)) throw new ClientError('INVALID_RESPONSE');
  for (let part = 1; part <= session.part_count; part += 1) {
    if (session.received_parts.includes(part)) continue;
    for (let attempt = 1; ; attempt += 1) {
      try {
        await putPart(invocation, bundle, part, session.part_size, { fetchImpl, runnerToken });
        break;
      } catch (error) {
        if (error instanceof ClientError && error.status && !transientStatus(error.status)) throw error;
        if (attempt >= MAX_ATTEMPTS) throw error instanceof ClientError ? error : new ClientError('UPLOAD_FAILED');
        await sleep(BACKOFF_MS[attempt - 1]);
        const refreshed = await begin();
        if (refreshed.part_size !== session.part_size || refreshed.part_count !== session.part_count) throw new ClientError('INVALID_RESPONSE');
        session = refreshed;
        if (session.received_parts.includes(part)) break;
      }
    }
  }
}

function stageFamily(stage) {
  if (!['sign', 'finalize', 'dmg_sign', 'dmg_finalize'].includes(stage)) throw new ClientError('INVALID_MANIFEST');
  const dmg = stage.startsWith('dmg_');
  const action = stage.endsWith('finalize') ? 'finalize' : 'sign';
  return { dmg, action };
}

function tempRoot() {
  const root = process.env.RUNNER_TEMP;
  if (!root || !path.isAbsolute(root)) throw new ClientError('TEMP_UNAVAILABLE');
  return path.resolve(root);
}

function invocationFromEnvironment(input) {
  return validateInvocation({ requestId: input.INPUT_REQUEST_ID, generation: input.INPUT_GENERATION, nonce: input.INPUT_NONCE,
    visibility: input.RUNNER_VISIBILITY, runId: input.GITHUB_RUN_ID, runAttempt: input.GITHUB_RUN_ATTEMPT });
}

async function makeRunDir(input) {
  const parent = tempRoot();
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const dir = await mkdtemp(path.join(parent, 'signing-client-'));
  await chmod(dir, 0o700);
  await writeFile(path.join(dir, '.signing-run'), `${input.requestId}\n${input.generation}\n`, { mode: 0o600, flag: 'wx' });
  return dir;
}

async function validateOutput(outputDir, manifest, verificationSchema) {
  const entries = await readdir(outputDir, { withFileTypes: true });
  if (!entries.some(entry => entry.name === 'verification.json' && entry.isFile()) || entries.some(entry => !entry.isFile() || entry.name !== 'verification.json' && !SAFE_OUTPUTS.has(entry.name))) throw new ClientError('INVALID_OUTPUT');
  const verification = verificationSchema.parse(JSON.parse(await readFile(path.join(outputDir, 'verification.json'), 'utf8')));
  if (verification.request_id !== manifest.request_id || verification.generation !== manifest.generation || verification.stage !== manifest.stage || verification.input_digest !== manifest.input_digest || verification.recipe_sha !== manifest.recipe_sha || verification.policy_digest !== manifest.policy_digest || verification.team_id !== manifest.team_id) throw new ClientError('INVALID_OUTPUT');
  const expectedOutput = { sign: 'signed.tar.gz', finalize: 'product.zip', dmg_sign: 'signed.dmg', dmg_finalize: 'product.dmg' }[manifest.stage];
  if (verification.files.length !== 1 || verification.files[0].path !== expectedOutput) throw new ClientError('INVALID_OUTPUT');
  for (const file of verification.files) {
    if (!SAFE_OUTPUTS.has(file.path) || !entries.some(entry => entry.name === file.path)) throw new ClientError('INVALID_OUTPUT');
    const info = await stat(path.join(outputDir, file.path));
    if (!info.isFile() || info.size !== file.size || info.size > manifest.max_artifact_bytes) throw new ClientError('INVALID_OUTPUT');
    const hasher = createHash('sha256');
    try { for await (const chunk of createReadStream(path.join(outputDir, file.path))) hasher.update(chunk); }
    catch { throw new ClientError('INVALID_OUTPUT'); }
    if (hasher.digest('hex') !== file.sha256) throw new ClientError('INVALID_OUTPUT');
  }
  return verification;
}

export async function execute({ input = process.env, fetchImpl = fetch, sleep = defaultSleep } = {}) {
  const { credentialsSchema, manifestSchema, verificationSchema } = await import('./contract.mjs');
  const invocation = invocationFromEnvironment(input);
  const api = createApi({ fetchImpl, runnerToken: input.SIGNING_RUNNER_TOKEN });
  const work = await makeRunDir(invocation);
  const inputZip = path.join(work, 'input.zip');
  const outputDir = path.join(work, 'output');
  await mkdir(outputDir, { mode: 0o700 });
  let heartbeatError;
  let timer;
  let heartbeatBusy = false;
  let heartbeatDone;
  let pulse;
  try {
    const claimed = await api('claim', invocation);
    const manifest = manifestSchema.parse(claimed.manifest);
    if (manifest.request_id !== invocation.requestId || manifest.generation !== invocation.generation) throw new ClientError('INVALID_MANIFEST');
    const stage = stageFamily(manifest.stage);
    pulse = async () => {
      if (heartbeatBusy) return;
      heartbeatBusy = true;
      heartbeatDone = api('heartbeat', invocation).catch(error => { heartbeatError = error; }).finally(() => { heartbeatBusy = false; });
      await heartbeatDone;
    };
    timer = setInterval(() => { void pulse(); }, 120_000);
    timer.unref?.();
    const transfer = { fetchImpl, runnerToken: input.SIGNING_RUNNER_TOKEN, sleep };
    await downloadObject(invocation, 'input', inputZip, { digest: manifest.input_digest, maxBytes: manifest.max_artifact_bytes, ...transfer });
    let templatePath;
    if (manifest.stage === 'dmg_sign') {
      templatePath = path.join(work, 'template.zip');
      await downloadObject(invocation, 'template', templatePath, { digest: manifest.template_digest, maxBytes: manifest.max_artifact_bytes, ...transfer });
    }
    let credentialsProvider;
    if (stage.action === 'sign') {
      let provided = false;
      credentialsProvider = async () => {
        if (provided) throw new ClientError('CREDENTIALS_ALREADY_REQUESTED');
        provided = true;
        if (heartbeatError) throw new ClientError('HEARTBEAT_FAILED');
        const authorized = await api('authorize-sign', invocation);
        const credentials = credentialsSchema.parse(authorized.credentials);
        return credentials;
      };
    } else {
      const authorized = await api('authorize-sign', invocation);
      if (authorized.credentials !== undefined) throw new ClientError('INVALID_RESPONSE');
    }
    const modulePath = stage.dmg ? './dmg.mjs' : './macos-sign.mjs';
    const executor = await import(modulePath);
    if (heartbeatError) throw new ClientError('HEARTBEAT_FAILED');
    if (stage.dmg && typeof executor.executeDmg !== 'function' || !stage.dmg && typeof executor.executeMacos !== 'function') throw new ClientError('EXECUTOR_UNAVAILABLE');
    if (stage.dmg) await executor.executeDmg(manifest, inputZip, outputDir, credentialsProvider, templatePath);
    else await executor.executeMacos(manifest, inputZip, outputDir, credentialsProvider);
    if (heartbeatError) throw new ClientError('HEARTBEAT_FAILED');
    const verification = await validateOutput(outputDir, manifest, verificationSchema);
    await chmod(outputDir, 0o700);
    await writeFile(path.join(outputDir, 'verification.json'), `${JSON.stringify(verification)}\n`, { mode: 0o600 });
    const bundle = await bundleOutput(outputDir, verification, work, manifest.max_artifact_bytes);
    await uploadOutput(invocation, bundle, { api, fetchImpl, runnerToken: input.SIGNING_RUNNER_TOKEN, sleep });
    if (heartbeatError) throw new ClientError('HEARTBEAT_FAILED');
    await api('complete', invocation, { output_archive_digest: bundle.digest, output_archive_size: bundle.size, verification_report: verification });
    return { workDir: work };
  } catch (error) {
    await rm(work, { recursive: true, force: true });
    throw error;
  } finally {
    if (timer) clearInterval(timer);
    if (heartbeatBusy && heartbeatDone) await heartbeatDone;
  }
}

export async function cleanup({ input = process.env } = {}) {
  const invocation = invocationFromEnvironment(input);
  const workDir = path.resolve(input.INPUT_WORK_DIR ?? '');
  const parent = tempRoot();
  if (path.dirname(workDir) !== parent || !path.basename(workDir).startsWith('signing-client-')) throw new ClientError('INVALID_TEMP_DIR');
  const marker = (await readFile(path.join(workDir, '.signing-run'), 'utf8')).split('\n');
  if (marker[0] !== invocation.requestId || marker[1] !== String(invocation.generation)) throw new ClientError('INVALID_TEMP_DIR');
  await rm(workDir, { recursive: true, force: true });
}

function setOutput(key, value) {
  const output = process.env.GITHUB_OUTPUT;
  if (!output) throw new ClientError('OUTPUT_UNAVAILABLE');
  return writeFile(output, `${key}=${value}\n`, { flag: 'a', mode: 0o600 });
}

export async function main(args = process.argv.slice(2)) {
  try {
    if (args[0] === 'execute') {
      const result = await execute();
      await setOutput('work_dir', result.workDir);
    } else if (args[0] === 'cleanup') await cleanup();
    else throw new ClientError('INVALID_COMMAND');
  } catch (error) {
    const native = error instanceof Error && /^(?:macOS signing operation failed: [a-z_]{1,64}|disk image operation failed: [a-z-]{1,64}|disk image cleanup failed)$/.test(error.message);
    const code = error instanceof ClientError ? error.code : native ? error.message : 'CLIENT_FAILED';
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
