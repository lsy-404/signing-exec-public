import { createHash, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createReadStream } from 'node:fs';
import { constants } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, mkdtemp, open, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { credentialsSchema, executableName, manifestSchema, sourceMetadataSchema, verificationSchema } from './contract.mjs';

delete process.env.DEBUG;
const require = createRequire(import.meta.url);
const { getRawHeader } = require('@electron/asar');
const { FuseState, FuseVersion, FuseV1Options, flipFuses, getCurrentFuseWire } = await import('@electron/fuses');
const { sign } = await import('@electron/osx-sign');

class RunnerFailure extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}
function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

async function fileSha256(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

async function snapshotArchive(source, destination, maxBytes, expectedDigest) {
  const input = await open(source, constants.O_RDONLY | constants.O_NOFOLLOW);
  let output;
  try {
    const metadata = await input.stat();
    if (!metadata.isFile() || metadata.size > maxBytes) throw new Error('input archive rejected');
    output = await open(destination, 'wx', 0o600);
    const hash = createHash('sha256');
    const buffer = Buffer.alloc(1024 * 1024);
    let position = 0;
    while (true) {
      const { bytesRead } = await input.read(buffer, 0, buffer.length, position);
      if (!bytesRead) break;
      position += bytesRead;
      if (position > maxBytes) throw new Error('input archive rejected');
      const block = buffer.subarray(0, bytesRead);
      hash.update(block);
      let offset = 0;
      while (offset < bytesRead) {
        const { bytesWritten } = await output.write(block, offset, bytesRead - offset, position - bytesRead + offset);
        if (!bytesWritten) throw new Error('input archive rejected');
        offset += bytesWritten;
      }
    }
    if (position !== metadata.size || `sha256:${hash.digest('hex')}` !== expectedDigest) throw new Error('input archive digest mismatch');
    return destination;
  } finally {
    await input.close();
    if (output) await output.close();
  }
}

async function command(file, args, options = {}) {
  try {
    const { timeout = 120_000, maxOutput = 8 * 1024 * 1024, ...spawnOptions } = options;
    return await new Promise((resolve, reject) => {
      const child = spawn(file, args, { ...spawnOptions, timeout, stdio: ['ignore', 'pipe', 'pipe'] });
      const stdout = [];
      const stderr = [];
      let bytes = 0;
      let failed = false;
      const collect = target => chunk => {
        bytes += chunk.length;
        if (bytes > maxOutput) {
          failed = true;
          child.kill();
          return;
        }
        target.push(chunk);
      };
      child.stdout.on('data', collect(stdout));
      child.stderr.on('data', collect(stderr));
      child.once('error', () => reject(new Error('command failed')));
      child.once('close', code => {
        if (failed || code !== 0) return reject(new Error('command failed'));
        resolve({ stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') });
      });
    });
  } catch {
    throw new Error('native signing command failed');
  }
}

async function ensureEmptyDirectory(directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const metadata = await lstat(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error('invalid output directory');
  const entries = await readdir(directory);
  if (entries.length) throw new Error('output directory must be empty');
}

function contained(root, target) {
  const relative = path.relative(root, target);
  return relative !== '' && !relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative);
}

async function readPlist(appPath, temporary) {
  const plist = path.join(appPath, 'Contents', 'Info.plist');
  const plistStat = await lstat(plist);
  if (!plistStat.isFile() || plistStat.isSymbolicLink() || plistStat.size > 1024 * 1024) throw new Error('invalid application metadata');
  const { stdout } = await command('/usr/bin/plutil', ['-convert', 'json', '-o', '-', plist]);
  const jsonPath = path.join(temporary, 'Info.json');
  await writeFile(jsonPath, stdout, { mode: 0o600 });
  return JSON.parse(await readFile(jsonPath, 'utf8'));
}

async function inspectBundle(appPath, manifest, temporary, requireSignatures, requireFuses = true) {
  const info = await readPlist(appPath, temporary);
  if (info.CFBundleIdentifier !== manifest.bundle_id || info.CFBundleShortVersionString !== manifest.version) {
    throw new Error('application identity mismatch');
  }
  if (!executableName.safeParse(info.CFBundleExecutable).success) {
    throw new Error('invalid application executable');
  }
  const executable = path.join(appPath, 'Contents', 'MacOS', info.CFBundleExecutable);
  const executableStat = await lstat(executable);
  if (!executableStat.isFile() || executableStat.isSymbolicLink() || !contained(path.resolve(appPath), path.resolve(executable))) {
    throw new Error('invalid application executable');
  }
  const { stdout: archOutput } = await command('/usr/bin/lipo', ['-archs', executable]);
  const architectures = new Set(archOutput.trim().split(/\s+/));
  const wanted = manifest.architecture === 'x64' ? ['x86_64'] : manifest.architecture === 'arm64' ? ['arm64'] : ['arm64', 'x86_64'];
  if (wanted.some(arch => !architectures.has(arch)) || (manifest.architecture !== 'universal' && architectures.size !== 1)) {
    throw new Error('application architecture mismatch');
  }

  let asarVerified = false;
  if (manifest.profile === 'electron') {
    const fuseFiles = [];
    if (manifest.architecture === 'universal') {
      const framework = path.join(appPath, 'Contents', 'Frameworks', 'Electron Framework.framework', 'Electron Framework');
      for (const arch of wanted) {
        const slice = path.join(temporary, `electron-${arch}`);
        await command('/usr/bin/lipo', [framework, '-thin', arch, '-output', slice]);
        fuseFiles.push(slice);
      }
    } else fuseFiles.push(executable);
    const required = [
      [FuseV1Options.RunAsNode, FuseState.DISABLE],
      [FuseV1Options.EnableNodeOptionsEnvironmentVariable, FuseState.DISABLE],
      [FuseV1Options.EnableNodeCliInspectArguments, FuseState.DISABLE],
      [FuseV1Options.EnableEmbeddedAsarIntegrityValidation, FuseState.ENABLE],
      [FuseV1Options.OnlyLoadAppFromAsar, FuseState.ENABLE],
    ];
    try {
      for (const file of fuseFiles) {
        const fuse = await getCurrentFuseWire(file);
        if (requireFuses && (fuse.version !== FuseVersion.V1 || required.some(([index, state]) => fuse[index] !== state))) throw new Error('application security policy mismatch');
      }
    } finally {
      if (manifest.architecture === 'universal') await Promise.all(fuseFiles.map(file => rm(file, { force: true })));
    }
    const asarPath = path.join(appPath, 'Contents', 'Resources', 'app.asar');
    const asarStat = await lstat(asarPath);
    if (!asarStat.isFile() || asarStat.isSymbolicLink() || asarStat.size > manifest.max_unpacked_bytes) throw new Error('invalid application archive');
    const header = getRawHeader(asarPath);
    const expected = info.ElectronAsarIntegrity?.['Resources/app.asar'];
    if (!expected || expected.algorithm !== 'SHA256' || expected.hash !== sha256(Buffer.from(header.headerString, 'utf8'))) {
      throw new Error('application archive integrity mismatch');
    }
    asarVerified = true;
  }

  if (requireSignatures) {
    await verifySignature(appPath,manifest);
  }
  return { asarVerified, info, executable };
}

async function createTar(archivePath, bundleName, baseDir) {
  await command('/usr/bin/tar', ['-czf', archivePath, '-C', baseDir, bundleName], {env:{...process.env,COPYFILE_DISABLE:'1'}});
}

async function identityHash(keychain, teamId) {
  const { stdout } = await command('/usr/bin/security', ['find-identity', '-v', '-p', 'codesigning', keychain]);
  for (const line of stdout.split('\n')) {
    const found = line.match(/\s([A-F0-9]{40})\s+"(Developer ID Application:[^"]+)"/);
    if (found && found[2].endsWith(`(${teamId})`)) return found[1];
  }
  throw new Error('approved signing identity unavailable');
}

async function keychainSearch(keychain, include) {
  const {stdout} = await command('/usr/bin/security',['list-keychains','-d','user']);
  const paths = stdout.split('\n').map(line=>line.trim()).filter(Boolean).map(line=>JSON.parse(line));
  if (paths.some(value=>typeof value!=='string'||!path.isAbsolute(value)||/[\r\n]/.test(value))) throw new Error('keychain search list invalid');
  const updated = paths.filter(value=>value!==keychain);
  if (include) updated.push(keychain);
  await command('/usr/bin/security',['list-keychains','-d','user','-s',...updated]);
}

function signingRequirement(teamId) {
  if (!/^[A-Z0-9]{10}$/.test(teamId)) throw new Error('invalid signing team');
  return `=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "${teamId}"`;
}

async function verifySignature(appPath, manifest) {
  try { await command('/usr/bin/codesign', ['--verify', '--deep', '--strict', '-R',signingRequirement(manifest.team_id),'--verbose=2', appPath]); }
  catch { throw new RunnerFailure('signature_chain'); }
  const { stderr, stdout } = await command('/usr/bin/codesign', ['-dv', '--verbose=4', appPath]);
  const details = `${stderr}\n${stdout}`;
  const team = details.match(/^TeamIdentifier=(.+)$/m)?.[1];
  const timestamp = details.match(/^Timestamp=(.+)$/m)?.[1];
  if (team !== manifest.team_id) throw new RunnerFailure('signature_team');
  if (!timestamp || timestamp === 'none') throw new RunnerFailure('signature_timestamp');
  return true;
}

async function outputFile(directory, name, content) {
  const target = path.join(directory, name);
  await writeFile(target, content, { mode: 0o600, flag: 'wx' });
  return { path: name, size: (await lstat(target)).size, sha256: await fileSha256(target) };
}

async function outputArchive(directory, name, source, maxBytes) {
  const sourceStat = await lstat(source);
  if (!sourceStat.isFile() || sourceStat.size > maxBytes) throw new Error('output archive exceeds approved limit');
  const target = path.join(directory, name);
  await copyFile(source, target, constants.COPYFILE_EXCL);
  await chmod(target, 0o600);
  return { path: name, size: sourceStat.size, sha256: await fileSha256(target) };
}

async function execute(manifestInput, inputArchivePath, outputDir, credentialsInput) {
  const manifest = manifestSchema.parse(manifestInput);
  if (!['sign','finalize'].includes(manifest.stage)) throw new Error('invalid application signing stage');
  if (manifest.stage === 'finalize' && credentialsInput !== undefined) throw new Error('credentials are not accepted during finalization');
  if (manifest.stage === 'sign' && typeof credentialsInput !== 'function' && (credentialsInput === null || typeof credentialsInput !== 'object')) {
    throw new Error('credentials provider required');
  }
  if (process.platform !== 'darwin') throw new Error('macOS native signing host required');
  const output = path.resolve(outputDir);
  await ensureEmptyDirectory(output);
  const work = await mkdtemp(path.join(os.tmpdir(), 'macos-sign-'));
  await chmod(work, 0o700);
  const extract = path.join(work, 'extract');
  const unpacker = path.join(path.dirname(fileURLToPath(import.meta.url)), 'unpack.py');
  const python = process.env.PYTHON || 'python3';
  let keychain;
  let failureCode = 'input_archive';
  try {
    const archiveSnapshot = await snapshotArchive(path.resolve(inputArchivePath), path.join(work, 'input.zip'), manifest.max_artifact_bytes, manifest.input_digest);
    await mkdir(extract, { mode: 0o700 });
    const config = JSON.stringify({ stage: manifest.stage, bundle_name: manifest.bundle_name, max_artifact_bytes: manifest.max_artifact_bytes, max_unpacked_bytes: manifest.max_unpacked_bytes, destination: extract });
    failureCode = 'archive_validation';
    await command(python, [unpacker, config, archiveSnapshot, work]);
    failureCode = 'source_binding';
    if (manifest.stage === 'sign') {
      const source = sourceMetadataSchema.parse(JSON.parse(await readFile(path.join(work, 'source.json'), 'utf8')));
      if (source.source_sha !== manifest.source_sha || source.version !== manifest.version || source.bundle_id !== manifest.bundle_id || source.architecture !== manifest.architecture) {
        throw new Error('source metadata does not match manifest');
      }
    }
    const appPath = path.join(extract, manifest.bundle_name);
    const appStat = await lstat(appPath);
    if (!appStat.isDirectory() || appStat.isSymbolicLink()) throw new Error('approved application bundle missing');
    failureCode = 'static_verification';
    let inspected = await inspectBundle(appPath, manifest, work, manifest.stage === 'finalize', !(manifest.stage==='sign'&&manifest.harden_electron_fuses));
    if (manifest.stage==='sign' && manifest.profile==='electron' && manifest.harden_electron_fuses) {
      await flipFuses(inspected.executable,{
        version:FuseVersion.V1,
        [FuseV1Options.RunAsNode]:false,
        [FuseV1Options.EnableNodeOptionsEnvironmentVariable]:false,
        [FuseV1Options.EnableNodeCliInspectArguments]:false,
        [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]:true,
        [FuseV1Options.OnlyLoadAppFromAsar]:true,
      });
      inspected = await inspectBundle(appPath,manifest,work,false);
    }

    if (manifest.stage === 'sign') {
      failureCode = 'credential_release';
      const suppliedCredentials = typeof credentialsInput === 'function' ? await credentialsInput() : credentialsInput;
      const credentials = credentialsSchema.parse(suppliedCredentials);
      const p12 = path.join(work, 'certificate.p12');
      const keyFile = path.join(work, 'notary.p8');
      const keychainPassword = randomBytes(32).toString('base64url');
      keychain = path.join(work, 'signing.keychain-db');
      await writeFile(p12, Buffer.from(credentials.certificate_p12, 'base64'), { mode: 0o600, flag: 'wx' });
      await writeFile(keyFile, credentials.notarization.private_key, { mode: 0o600, flag: 'wx' });
      await command('/usr/bin/security', ['create-keychain', '-p', keychainPassword, keychain]);
      await command('/usr/bin/security', ['set-keychain-settings', '-lut', '300', keychain]);
      await command('/usr/bin/security', ['unlock-keychain', '-p', keychainPassword, keychain]);
      failureCode = 'keychain_import';
      const publicIntermediate = fileURLToPath(new URL('./certificates/developer-id-g2.cer', import.meta.url));
      await command('/usr/bin/security', ['import', publicIntermediate, '-k', keychain, '-T', '/usr/bin/codesign']);
      await command('/usr/bin/security', ['import', p12, '-k', keychain, '-P', credentials.certificate_password, '-T', '/usr/bin/codesign']);
      await command('/usr/bin/security', ['set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:', '-s', '-k', keychainPassword, keychain]);
      await keychainSearch(keychain,true);
      const identity = await identityHash(keychain, manifest.team_id);
      failureCode = 'codesign';
      try {
        await sign({ app: appPath, identity, keychain, hardenedRuntime: true, preAutoEntitlements: false, preEmbedProvisioningProfile: false, platform: 'darwin', type: 'distribution', strictVerify: true });
      } catch (error) {
        const detail = error instanceof Error ? error.message : '';
        const categories = [
          ['identity',/identity|certificate.*not found|no identity/i],
          ['chain',/unable to build chain|CSSMERR_TP_NOT_TRUSTED/i],
          ['acl',/errSecInternalComponent|User interaction is not allowed/i],
          ['resources',/resource fork|Finder information|unsealed contents/i],
          ['unsigned_child',/code object is not signed at all/i],
          ['timestamp',/timestamp|time stamp/i],
          ['options',/invalid option|unknown option|invalid.*entitlement/i],
        ];
        failureCode = 'codesign_'+(categories.find(([,pattern])=>pattern.test(detail))?.[0]??'failed');
        throw new Error('application signing failed');
      }
      failureCode = 'signature_verification';
      await verifySignature(appPath, manifest);
      failureCode = 'notarization';
      const notarizeZip = path.join(work, 'notarize.zip');
      await command('/usr/bin/ditto', ['-c', '-k', '--keepParent', appPath, notarizeZip]);
      if ((await lstat(notarizeZip)).size > manifest.max_artifact_bytes) throw new Error('notarization archive exceeds approved limit');
      const notaryHash = await fileSha256(notarizeZip);
      const notary = credentials.notarization;
      const { stdout } = await command('/usr/bin/xcrun', ['notarytool', 'submit', notarizeZip, '--key', keyFile, '--key-id', notary.key_id, '--issuer', notary.issuer_id, '--output-format', 'json']);
      let receipt;
      try { receipt = JSON.parse(stdout); } catch { throw new Error('Apple notarization receipt invalid'); }
      const notarizationId = receipt.id;
      if (typeof notarizationId !== 'string' || !/^[0-9a-f-]{36}$/i.test(notarizationId)) throw new Error('Apple notarization receipt invalid');
      failureCode = 'artifact_packaging';
      const signedTar = path.join(work, 'signed.tar.gz');
      await createTar(signedTar, manifest.bundle_name, extract);
      const files = [await outputArchive(output, 'signed.tar.gz', signedTar, manifest.max_artifact_bytes)];
      const report = verificationSchema.parse({ schema_version: 1, request_id: manifest.request_id, generation: manifest.generation, stage: 'sign', input_digest: manifest.input_digest, recipe_sha: manifest.recipe_sha, policy_digest: manifest.policy_digest, team_id: manifest.team_id, bundle_id: manifest.bundle_id, version: manifest.version, architecture: manifest.architecture, codesign_verified: true, timestamp_verified: true, asar_integrity_verified: inspected.asarVerified, notarization_id: notarizationId, notarization_status: 'Submitted', notary_archive_sha256: notaryHash, gatekeeper_verified: false, staple_verified: false, files });
      await outputFile(output, 'verification.json', Buffer.from(JSON.stringify(report)));
      return report;
    }

    failureCode = 'stapling';
    const stapleAttempts = 3;
    let stapled = false;
    for (let attempt = 0; attempt < stapleAttempts; attempt++) {
      try {
        await command('/usr/bin/xcrun', ['stapler', 'staple', appPath], { timeout: 60_000 });
        stapled = true;
        break;
      } catch {
        if (attempt < stapleAttempts - 1) await new Promise(resolve => setTimeout(resolve, 1500 * (attempt + 1)));
      }
    }
    if (!stapled) throw new Error('notarization ticket stapling failed');
    failureCode = 'gatekeeper_verification';
    await command('/usr/bin/xcrun', ['stapler', 'validate', appPath], { timeout: 60_000 });
    await command('/usr/sbin/spctl', ['--assess', '--type', 'execute', '--verbose=2', appPath]);
    await verifySignature(appPath, manifest);
    failureCode = 'artifact_packaging';
    const productZip = path.join(work, 'product.zip');
    await command('/usr/bin/ditto', ['-c', '-k', '--keepParent', appPath, productZip]);
    const files = [await outputArchive(output, 'product.zip', productZip, manifest.max_artifact_bytes)];
    const report = verificationSchema.parse({ schema_version: 1, request_id: manifest.request_id, generation: manifest.generation, stage: 'finalize', input_digest: manifest.input_digest, recipe_sha: manifest.recipe_sha, policy_digest: manifest.policy_digest, team_id: manifest.team_id, bundle_id: manifest.bundle_id, version: manifest.version, architecture: manifest.architecture, codesign_verified: true, timestamp_verified: true, asar_integrity_verified: inspected.asarVerified, notarization_id: manifest.notarization_id, notarization_status: 'Accepted', notary_archive_sha256: manifest.notary_archive_sha256, gatekeeper_verified: true, staple_verified: true, files });
    await outputFile(output, 'verification.json', Buffer.from(JSON.stringify(report)));
    return report;
  } catch (error) {
    await rm(output, { recursive: true, force: true });
    await mkdir(output, { recursive: true, mode: 0o700 });
    throw error instanceof RunnerFailure ? error : new RunnerFailure(failureCode);
  } finally {
    let cleanupFailed = false;
    if (keychain) {
      try { await keychainSearch(keychain,false); }
      catch { cleanupFailed = true; }
      try { await command('/usr/bin/security', ['delete-keychain', keychain]); }
      catch { cleanupFailed = true; }
    }
    await rm(work, { recursive: true, force: true });
    if (cleanupFailed) {
      await rm(output, { recursive: true, force: true });
      await mkdir(output, { recursive: true, mode: 0o700 });
      throw new RunnerFailure('keychain_cleanup');
    }
  }
}

export async function executeMacos(manifest, inputArchivePath, outputDir, credentials) {
  try {
    return verificationSchema.parse(await execute(manifest, inputArchivePath, outputDir, credentials));
  } catch (error) {
    if (error instanceof RunnerFailure) throw new Error(`macOS signing operation failed: ${error.code}`);
    throw new Error('macOS signing operation failed');
  }
}

export { command, createTar, fileSha256, identityHash, inspectBundle, keychainSearch, signingRequirement, snapshotArchive };
