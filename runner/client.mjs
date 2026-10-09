import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';

const API_ORIGIN = 'https://sign.voidcarve.com';
const MAX_JSON_BYTES = 1_000_000;
const ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NONCE_RE = /^[A-Za-z0-9_-]{43}$/;
const RUNNER_TOKEN_RE = /^vcr_[A-Za-z0-9_-]{43}$/;
const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;
const ARTIFACT_HOSTS = [/^productionresultssa\d+\.blob\.core\.windows\.net$/, /^pipelines\.actions\.githubusercontent\.com$/, /^results-receiver\.actions\.githubusercontent\.com$/];
const SAFE_OUTPUTS = new Set(['signed.tar.gz', 'product.zip', 'signed.dmg', 'product.dmg']);

export class ClientError extends Error {
  constructor(code) { super(code); this.code = code; }
}

export function validateInvocation(input) {
  if (!input || !ID_RE.test(input.requestId ?? '') || !/^[1-9]\d*$/.test(input.generation ?? '') || !NONCE_RE.test(input.nonce ?? '')) throw new ClientError('INVALID_INPUT');
  const generation = Number(input.generation);
  const runId = Number(input.runId);
  if (!Number.isSafeInteger(generation) || generation < 1 || !/^[1-9]\d*$/.test(String(input.runId ?? '')) || !Number.isSafeInteger(runId) || String(input.runAttempt) !== '1') throw new ClientError('INVALID_INPUT');
  if (input.visibility !== 'public' && input.visibility !== 'private') throw new ClientError('INVALID_INPUT');
  return { requestId: input.requestId, generation, nonce: input.nonce, visibility: input.visibility, runId, runAttempt: 1 };
}

export function validateArtifactUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new ClientError('INVALID_DOWNLOAD_URL'); }
  if (url.protocol !== 'https:' || url.port && url.port !== '443' || url.username || url.password || url.hash || !ARTIFACT_HOSTS.some(pattern => pattern.test(url.hostname))) throw new ClientError('INVALID_DOWNLOAD_URL');
  return url;
}

export function validateRoute(action) {
  if (!['claim', 'input', 'authorize-sign', 'heartbeat', 'complete'].includes(action)) throw new ClientError('INVALID_ROUTE');
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
  if (action === 'input' && (!DIGEST_RE.test(body.digest ?? '') || !Number.isSafeInteger(body.max_bytes) || body.max_bytes < 1 || body.max_bytes > 2_000_000_000 || typeof body.download_url !== 'string')) throw new ClientError('INVALID_RESPONSE');
  if (action === 'authorize-sign' && (typeof body.operation_id !== 'string' || !/^[A-Za-z0-9_:-]{16,128}$/.test(body.operation_id))) throw new ClientError('INVALID_RESPONSE');
  if (action === 'heartbeat' && (!Number.isSafeInteger(body.lease_until) || body.lease_until <= Date.now())) throw new ClientError('INVALID_RESPONSE');
  if (action === 'complete' && body.state !== 'verifying') throw new ClientError('INVALID_RESPONSE');
  return body;
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
      if (response.status !== 202) throw new ClientError('API_REQUEST_FAILED');
    } else if (!response.ok) {
      const detail = await parseJson(response).catch(() => null);
      throw new ClientError(typeof detail?.error === 'string' && /^[a-z_]{1,64}$/.test(detail.error) ? `API_${detail.error.toUpperCase()}` : 'API_REQUEST_FAILED');
    }
    return validateActionResult(action, await parseJson(response));
  };
}

export async function downloadVerified(urlValue, destination, { digest, maxBytes, fetchImpl = fetch }) {
  const url = validateArtifactUrl(urlValue);
  if (!DIGEST_RE.test(digest ?? '') || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 2_000_000_000) throw new ClientError('INVALID_DOWNLOAD_METADATA');
  const response = await fetchImpl(url, { redirect: 'error' });
  if (!response.ok || !response.body) throw new ClientError('DOWNLOAD_FAILED');
  const hasher = createHash('sha256');
  let size = 0;
  const meter = new Transform({ transform(chunk, _encoding, callback) {
    size += chunk.length;
    if (size > maxBytes) return callback(new ClientError('DOWNLOAD_TOO_LARGE'));
    hasher.update(chunk);
    callback(null, chunk);
  } });
  try {
    await pipeline(response.body, meter, createWriteStream(destination, { flags: 'wx', mode: 0o600 }));
  } catch (error) {
    await rm(destination, { force: true });
    throw error instanceof ClientError ? error : new ClientError('DOWNLOAD_FAILED');
  }
  if (`sha256:${hasher.digest('hex')}` !== digest) {
    await rm(destination, { force: true });
    throw new ClientError('DOWNLOAD_DIGEST_MISMATCH');
  }
  return { size };
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

export async function execute({ input = process.env, fetchImpl = fetch } = {}) {
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
    const inputInfo = await api('input', invocation);
    if (inputInfo.digest !== manifest.input_digest) throw new ClientError('INVALID_RESPONSE');
    if (manifest.stage === 'dmg_sign' && typeof inputInfo.template_download_url !== 'string') throw new ClientError('INVALID_RESPONSE');
    await downloadVerified(inputInfo.download_url, inputZip, { digest: inputInfo.digest, maxBytes: inputInfo.max_bytes, fetchImpl });
    let templatePath;
    if (manifest.stage === 'dmg_sign') {
      if (typeof inputInfo.template_download_url !== 'string' || !DIGEST_RE.test(inputInfo.template_digest ?? '')) throw new ClientError('INVALID_RESPONSE');
      templatePath = path.join(work, 'template.zip');
      await downloadVerified(inputInfo.template_download_url, templatePath, { digest: inputInfo.template_digest, maxBytes: inputInfo.max_bytes, fetchImpl });
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
    const reportPath = path.join(outputDir, 'verification.json');
    await writeFile(reportPath, `${JSON.stringify(verification)}\n`, { mode: 0o600 });
    return { workDir: work, outputDir, reportPath };
  } catch (error) {
    await rm(work, { recursive: true, force: true });
    throw error;
  } finally {
    if (timer) clearInterval(timer);
    if (heartbeatBusy && heartbeatDone) await heartbeatDone;
  }
}

export async function complete({ input = process.env, fetchImpl = fetch } = {}) {
  const invocation = invocationFromEnvironment(input);
  const outputArtifactId = Number(input.INPUT_ARTIFACT_ID);
  const outputArchiveDigest = input.INPUT_ARTIFACT_DIGEST;
  if (!Number.isSafeInteger(outputArtifactId) || outputArtifactId<1 || !DIGEST_RE.test(outputArchiveDigest ?? '')) throw new ClientError('INVALID_INPUT');
  const workDir = path.resolve(input.INPUT_WORK_DIR ?? '');
  const parent = tempRoot();
  if (path.dirname(workDir) !== parent || !path.basename(workDir).startsWith('signing-client-')) throw new ClientError('INVALID_TEMP_DIR');
  const marker = (await readFile(path.join(workDir, '.signing-run'), 'utf8')).split('\n');
  if (marker[0] !== invocation.requestId || marker[1] !== String(invocation.generation)) throw new ClientError('INVALID_TEMP_DIR');
  const reportPath = path.join(workDir, 'output', 'verification.json');
  const { verificationSchema } = await import('./contract.mjs');
  const verification = verificationSchema.parse(JSON.parse(await readFile(reportPath, 'utf8')));
  if (verification.request_id !== invocation.requestId || verification.generation !== invocation.generation) throw new ClientError('INVALID_OUTPUT');
  const api = createApi({ fetchImpl, runnerToken: input.SIGNING_RUNNER_TOKEN });
  await api('complete', invocation, { output_artifact_id: outputArtifactId, output_archive_digest: outputArchiveDigest, verification_report: verification });
  return { state: 'verifying' };
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
      await setOutput('output_dir', result.outputDir);
      await setOutput('report_path', result.reportPath);
    } else if (args[0] === 'complete') await complete();
    else if (args[0] === 'cleanup') await cleanup();
    else throw new ClientError('INVALID_COMMAND');
  } catch (error) {
    const native = error instanceof Error && /^(?:macOS signing operation failed: [a-z_]{1,64}|disk image operation failed: [a-z-]{1,64}|disk image cleanup failed)$/.test(error.message);
    const code = error instanceof ClientError ? error.code : native ? error.message : 'CLIENT_FAILED';
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
