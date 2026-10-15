import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { createReadStream } from 'node:fs';
import { chmod, copyFile, cp, lstat, mkdir, mkdtemp, open, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pipeline } from 'node:stream/promises';
import yauzl from 'yauzl';
import { Arch, Platform, build } from 'electron-builder';
import { createRequire } from 'node:module';
import { sourceMetadataSchema, windowsManifestSchema, windowsVerificationSchema } from './contract.mjs';

const SUBJECT = 'CN=VOIDCARVE LABS, O=VOIDCARVE LABS, L=Mississauga, S=Ontario, C=CA';
const TIMESTAMP_URL = 'http://timestamp.acs.microsoft.com';
const SIGNABLE_EXTENSIONS = new Set(['.exe', '.dll', '.node']);
const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const POWERSHELL = 'pwsh.exe';

class RunnerFailure extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

async function fileSha256(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

async function run(file, args, { timeout = 300_000, maxOutput = 8 * 1024 * 1024, cwd, env } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { cwd, env, timeout, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = [];
    const stderr = [];
    let length = 0;
    let overflow = false;
    const collect = target => chunk => {
      length += chunk.length;
      if (length > maxOutput) {
        overflow = true;
        child.kill();
      } else target.push(chunk);
    };
    child.stdout.on('data', collect(stdout));
    child.stderr.on('data', collect(stderr));
    child.once('error', () => reject(new Error('trusted command unavailable')));
    child.once('close', code => {
      if (overflow || code !== 0) return reject(new Error('trusted command failed'));
      resolve({ stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') });
    });
  });
}

function contained(root, target) {
  const relative = path.relative(root, target);
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function validateWindowsPath(name, directory) {
  if (typeof name !== 'string' || !name || name.includes('\\') || name.startsWith('/') || /^[A-Za-z]:/.test(name)) throw new Error('invalid archive path');
  if (/[\u0000-\u001f\u007f]/.test(name)) throw new Error('invalid archive path');
  const raw = directory && name.endsWith('/') ? name.slice(0, -1) : name;
  if (!raw || raw.endsWith('/') || raw.split('/').some(segment => !segment || segment === '.' || segment === '..')) throw new Error('invalid archive path');
  const segments = raw.split('/');
  for (const segment of segments) {
    if (segment.endsWith('.') || segment.endsWith(' ') || /[<>:"|?*]/.test(segment)) throw new Error('invalid Windows filename');
    if (Buffer.byteLength(segment, 'utf16le') / 2 > 255) throw new Error('Windows filename too long');
    if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i.test(segment)) throw new Error('reserved Windows filename');
  }
  if (Buffer.byteLength(raw, 'utf16le') / 2 > 240) throw new Error('Windows path too long');
  return { raw };
}

function addArchivePath(nodes, name, kind) {
  const normalized = name.normalize('NFC');
  const parts = normalized.split('/');
  for (let index = 0; index < parts.length; index++) {
    const item = parts.slice(0, index + 1).join('/');
    const wanted = index === parts.length - 1 ? kind : 'directory';
    const key = item.toLocaleLowerCase('en-US');
    const previous = nodes.get(key);
    const explicit = index === parts.length - 1;
    if (previous && (previous.path !== item || previous.kind !== wanted || (explicit && previous.explicit))) throw new Error('archive path collision');
    nodes.set(key, { path: item, kind: wanted, explicit: previous?.explicit || explicit });
  }
}

function openZip(file) {
  return new Promise((resolve, reject) => {
    yauzl.open(file, { lazyEntries: true, decodeStrings: true, validateEntrySizes: true, strictFileNames: false, autoClose: false }, (error, zip) => {
      if (error) reject(error);
      else resolve(zip);
    });
  });
}

function entryStream(zip, entry) {
  return new Promise((resolve, reject) => {
    zip.openReadStream(entry, (error, stream) => error ? reject(error) : resolve(stream));
  });
}

async function snapshotArchive(source, destination, maxBytes, expectedDigest) {
  const metadata = await lstat(source);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > maxBytes) throw new Error('input archive rejected');
  const input = await open(source, constants.O_RDONLY);
  let output;
  try {
    const opened = await input.stat();
    if (!opened.isFile() || opened.size !== metadata.size) throw new Error('input archive changed');
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
        if (!bytesWritten) throw new Error('input archive copy failed');
        offset += bytesWritten;
      }
    }
    if (position !== opened.size || `sha256:${hash.digest('hex')}` !== expectedDigest) throw new Error('input archive digest mismatch');
  } finally {
    await input.close();
    if (output) await output.close();
  }
  return destination;
}

async function extractInput(archivePath, destination, manifest) {
  const zip = await openZip(archivePath);
  const nodes = new Map();
  const entries = [];
  let declaredBytes = 0;
  try {
    await new Promise((resolve, reject) => {
      zip.on('error', reject);
      zip.on('entry', entry => {
        try {
          if (entries.length >= 200_000 || (entry.generalPurposeBitFlag & 1) !== 0) throw new Error('archive entry rejected');
          const isDirectory = entry.fileName.endsWith('/');
          const { raw } = validateWindowsPath(entry.fileName, isDirectory);
          if (raw !== 'app' && raw !== 'source.json' && !raw.startsWith('app/')) throw new Error('unexpected archive root entry');
          if (raw === 'app' && !isDirectory) throw new Error('application root must be a directory');
          const unixMode = (entry.externalFileAttributes >>> 16) & 0xffff;
          const fileType = unixMode & 0xf000;
          const dosAttributes = entry.externalFileAttributes & 0xffff;
          if ((dosAttributes & 0x0400) !== 0 || [0xa000, 0x6000, 0x2000, 0x1000].includes(fileType)) throw new Error('links and special files are forbidden');
          if (fileType !== 0 && fileType !== (isDirectory ? 0x4000 : 0x8000)) throw new Error('archive entry type rejected');
          if (isDirectory && entry.uncompressedSize !== 0) throw new Error('directory data rejected');
          if (raw === 'source.json' && (isDirectory || entry.uncompressedSize > 64 * 1024)) throw new Error('source metadata rejected');
          addArchivePath(nodes, raw, isDirectory ? 'directory' : 'file');
          declaredBytes += entry.uncompressedSize;
          if (declaredBytes > manifest.max_unpacked_bytes) throw new Error('archive exceeds approved unpacked size');
          entries.push({ entry, raw, isDirectory });
          zip.readEntry();
        } catch (error) {
          reject(error);
        }
      });
      zip.on('end', resolve);
      zip.readEntry();
    });
    if (!nodes.has('app') || !nodes.has('source.json')) throw new Error('source layout rejected');
    await mkdir(destination, { recursive: false, mode: 0o700 });
    for (const { entry, raw, isDirectory } of entries) {
      const target = path.resolve(destination, ...raw.split('/'));
      if (!contained(path.resolve(destination), target)) throw new Error('archive path escaped extraction root');
      if (Buffer.byteLength(target, 'utf16le') / 2 > 240) throw new Error('Windows extraction path too long');
      if (isDirectory) {
        await mkdir(target, { recursive: true, mode: 0o700 });
      } else {
        await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
        const stream = await entryStream(zip, entry);
        await pipeline(stream, (await import('node:fs')).createWriteStream(target, { flags: 'wx', mode: 0o600 }));
      }
    }
    const source = sourceMetadataSchema.parse(JSON.parse(await readFile(path.join(destination, 'source.json'), 'utf8')));
    if (source.source_sha !== manifest.source_sha || source.version !== manifest.version || source.bundle_id !== manifest.bundle_id || source.architecture !== manifest.architecture) {
      throw new Error('source metadata does not match manifest');
    }
    const appDir = path.join(destination, 'app');
    const appStat = await lstat(appDir);
    if (!appStat.isDirectory() || appStat.isSymbolicLink()) throw new Error('application directory rejected');
    return appDir;
  } finally {
    zip.close();
  }
}

async function walkSignableFiles(root) {
  const found = [];
  const pending = [root];
  while (pending.length) {
    const directory = pending.pop();
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const target = path.join(directory, entry.name);
      const metadata = await lstat(target);
      if (metadata.isSymbolicLink() || !contained(root, target)) throw new Error('application link rejected');
      if (metadata.isDirectory()) pending.push(target);
      else if (metadata.isFile() && SIGNABLE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) found.push(target);
      else if (!metadata.isFile()) throw new Error('special application file rejected');
    }
  }
  return found.sort((left, right) => left.localeCompare(right, 'en'));
}

async function inspectPeArchitecture(file) {
  const handle = await open(file, constants.O_RDONLY);
  try {
    const metadata = await handle.stat();
    const dos = Buffer.alloc(64);
    if (metadata.size < dos.length || (await handle.read(dos, 0, dos.length, 0)).bytesRead !== dos.length || dos.readUInt16LE(0) !== 0x5a4d) throw new Error('invalid PE executable');
    const peOffset = dos.readUInt32LE(0x3c);
    if (peOffset > metadata.size - 6 || peOffset > 16 * 1024 * 1024) throw new Error('invalid PE executable');
    const header = Buffer.alloc(6);
    if ((await handle.read(header, 0, header.length, peOffset)).bytesRead !== header.length || header.toString('ascii', 0, 4) !== 'PE\0\0') throw new Error('invalid PE executable');
    const machine = header.readUInt16LE(4);
    if (machine === 0x8664) return 'x64';
    if (machine === 0xaa64) return 'arm64';
    throw new Error('unsupported PE architecture');
  } finally {
    await handle.close();
  }
}

function normalizeProductVersion(value) {
  const normalized = value.trim();
  return normalized.match(/^(\d+\.\d+\.\d+)\.0$/)?.[1] ?? normalized;
}

async function ensureEmptyDirectory(directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const metadata = await lstat(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || (await readdir(directory)).length) throw new Error('output directory must be empty');
}

async function readJsonOutput(result) {
  const candidates = result.stdout.split(/\r?\n/).map(line => line.trim()).filter(line => line.startsWith('{') && line.endsWith('}'));
  if (!candidates.length) throw new Error('trusted command response missing');
  return JSON.parse(candidates.at(-1));
}

async function invokePowerShell(script, mode, configPath, filePath) {
  const result = await run(POWERSHELL, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', script, '-Mode', mode, '-ConfigPath', configPath, '-FilePath', filePath]);
  if (mode === 'SignFolder') return {};
  return readJsonOutput(result);
}

async function copyOutput(source, output, name, maxBytes) {
  const metadata = await lstat(source);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 1 || metadata.size > maxBytes) throw new Error('invalid packaging output');
  const target = path.join(output, name);
  await copyFile(source, target, constants.COPYFILE_EXCL);
  await chmod(target, 0o600);
  return { path: name, size: metadata.size, sha256: await fileSha256(target) };
}

function trustedHookSource(script, config, failureMarker) {
  const scriptArg = JSON.stringify(script);
  const configArg = JSON.stringify(config);
  const markerArg = JSON.stringify(failureMarker);
  return `const { spawnSync } = require('node:child_process');\nconst { writeFileSync } = require('node:fs');\nmodule.exports = function(file) {\n  try {\n    const base = ['-NoLogo','-NoProfile','-NonInteractive','-File',${scriptArg},'-ConfigPath',${configArg},'-FilePath',file];\n    const verify = spawnSync('pwsh.exe', [...base.slice(0, 5), '-Mode', 'Verify', ...base.slice(5)], { stdio: 'inherit', windowsHide: true, timeout: 300000 });\n    if (!verify.error && verify.status === 0) return;\n    const sign = spawnSync('pwsh.exe', [...base.slice(0, 5), '-Mode', 'Sign', ...base.slice(5)], { stdio: 'inherit', windowsHide: true, timeout: 300000 });\n    if (sign.error || sign.status !== 0) throw new Error('Windows signature verification failed');\n  } catch (error) {\n    try { writeFileSync(${markerArg}, 'failed', { flag: 'wx' }); } catch {}\n    throw error;\n  }\n};\n`;
}

async function prepareSquirrelVendor(work, installerModule) {
  const packageDir = path.dirname(installerModule);
  const vendorSource = path.join(packageDir, '..', 'vendor');
  const vendorTarget = path.join(work, 'squirrel-vendor');
  await cp(vendorSource, vendorTarget, { recursive: true, dereference: false, errorOnExist: true });
  const archSuffix = process.arch === 'arm64' ? 'arm64' : process.arch === 'x64' ? 'x64' : null;
  if (!archSuffix) throw new Error('unsupported Windows runner architecture');
  await copyFile(path.join(vendorTarget, `7z-${archSuffix}.exe`), path.join(vendorTarget, '7z.exe'));
  await copyFile(path.join(vendorTarget, `7z-${archSuffix}.dll`), path.join(vendorTarget, '7z.dll'));
  return vendorTarget;
}

async function collectReportFiles(output, manifest, productName) {
  const entries = await readdir(output);
  const products = entries.filter(name => name !== 'verification.json');
  if (manifest.windows.installer === 'nsis') {
    const expected = ['product.exe', ...(manifest.windows.portable ? ['product-portable.exe'] : [])].sort();
    if (products.sort().join('\n') !== expected.join('\n')) throw new Error('NSIS outputs do not match recipe');
  } else {
    const packages = products.filter(name => /^[A-Za-z0-9][A-Za-z0-9_.-]*-full\.nupkg$/.test(name));
    if (packages.length !== 1 || !packages[0].startsWith(`${productName}-`)) throw new Error('Squirrel package name mismatch');
    const expected = ['product.exe', 'RELEASES', packages[0]].sort();
    if (products.sort().join('\n') !== expected.join('\n')) throw new Error('Squirrel outputs do not match recipe');
  }
  const files = [];
  for (const name of products.sort()) {
    const metadata = await lstat(path.join(output, name));
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 1 || metadata.size > manifest.max_artifact_bytes) throw new Error('output file rejected');
    files.push({ path: name, size: metadata.size, sha256: await fileSha256(path.join(output, name)) });
  }
  return files;
}

async function signNsis(manifest, appDir, work, output, signOne, signScript, configPath) {
  const projectDir = path.join(work, 'builder-project');
  const buildDir = path.join(work, 'builder-output');
  await mkdir(projectDir, { recursive: false, mode: 0o700 });
  await mkdir(buildDir, { recursive: false, mode: 0o700 });
  const packageName = `${manifest.windows.product_name}-${manifest.architecture}`.toLowerCase().replace(/[^a-z0-9_.-]/g, '-');
  const packageJson = {
    name: packageName,
    version: manifest.version,
    productName: manifest.windows.product_name,
    description: manifest.windows.product_name,
    author: 'VOIDCARVE LABS',
  };
  await writeFile(path.join(projectDir, 'package.json'), JSON.stringify(packageJson), { flag: 'wx', mode: 0o600 });
  const name = manifest.windows.executable_name.slice(0, -4);
  await build({
    targets: Platform.WINDOWS.createTarget(['nsis', ...(manifest.windows.portable ? ['portable'] : [])], manifest.architecture === 'x64' ? Arch.x64 : Arch.arm64),
    projectDir,
    prepackaged: appDir,
    config: {
      extends: null,
      appId: manifest.bundle_id,
      productName: manifest.windows.product_name,
      electronVersion: manifest.windows.electron_version,
      directories: { output: buildDir },
      win: {
        icon: path.join(appDir,'resources','installer.ico'),
        executableName: name,
        target: ['nsis', ...(manifest.windows.portable ? ['portable'] : [])],
        signExts: ['.exe', '.EXE', '.dll', '.DLL', '.node', '.NODE'],
        signExecutable: true,
        signtoolOptions: {
          publisherName: 'VOIDCARVE LABS',
          signingHashAlgorithms: ['sha256'],
          rfc3161TimeStampServer: TIMESTAMP_URL,
          sign: async task => signOne(task.path),
        },
      },
      nsis: {
        installerIcon: path.join(appDir,'resources','installer.ico'),
        uninstallerIcon: path.join(appDir,'resources','installer.ico'),
        oneClick: false,
        perMachine: false,
        allowToChangeInstallationDirectory: false,
        artifactName: 'product.exe',
      },
      portable: { artifactName: 'product-portable.exe' },
      publish: null,
    },
  });
  const products = ['product.exe', ...(manifest.windows.portable ? ['product-portable.exe'] : [])];
  for (const filename of products) await invokePowerShell(signScript, 'Verify', configPath, path.join(buildDir, filename));
  for (const filename of products) {
    const source = path.join(buildDir, filename);
    await copyOutput(source, output, filename, manifest.max_artifact_bytes);
  }
  const originalAppFiles = await walkSignableFiles(appDir);
  for (const file of originalAppFiles) await invokePowerShell(signScript, 'Verify', configPath, file);
}

async function signSquirrel(manifest, appDir, work, output, signScript, configPath) {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/.test(manifest.windows.product_name)) throw new Error('Squirrel product name is not package-safe');
  const packageName = `${manifest.windows.product_name}-${manifest.architecture}`;
  const buildDir = path.join(work, 'squirrel-output');
  await mkdir(buildDir, { recursive: false, mode: 0o700 });
  const hookModule = path.join(work, 'squirrel-sign-hook.cjs');
  const hookFailureMarker = path.join(work, 'squirrel-signing-failed');
  await writeFile(hookModule, trustedHookSource(signScript, configPath, hookFailureMarker), { flag: 'wx', mode: 0o600 });
  const tempDirectory = path.join(work, 'squirrel-temp');
  await mkdir(tempDirectory, { recursive: false, mode: 0o700 });
  const installerModule = path.join(REPOSITORY_ROOT, 'runner', 'node_modules', 'electron-winstaller', 'lib', 'index.js');
  const vendorDirectory = await prepareSquirrelVendor(work, installerModule);
  const squirrelExecutable = path.join(vendorDirectory, 'Squirrel.exe');
  await invokePowerShell(signScript, 'Sign', configPath, squirrelExecutable);
  await invokePowerShell(signScript, 'Verify', configPath, squirrelExecutable);
  const previousTemp = process.env.TEMP;
  const previousTmp = process.env.TMP;
  let packageVersion;
  process.env.TEMP = tempDirectory;
  process.env.TMP = tempDirectory;
  try {
    if (path.resolve(os.tmpdir()).toLowerCase() !== path.resolve(tempDirectory).toLowerCase()) throw new Error('Squirrel temporary directory was not selected');
    const { convertVersion, createWindowsInstaller } = await import('electron-winstaller');
    const requireInstaller = createRequire(installerModule);
    if (path.resolve(requireInstaller('temp').dir).toLowerCase() !== path.resolve(tempDirectory).toLowerCase()) {
      throw new Error('Squirrel dependency temporary directory was not selected');
    }
    packageVersion = convertVersion(manifest.version);
    await createWindowsInstaller({
      appDirectory: appDir,
      outputDirectory: buildDir,
      vendorDirectory,
      name: packageName,
      title: manifest.windows.product_name,
      productName: manifest.windows.product_name,
      version: packageVersion,
      exe: manifest.windows.executable_name,
      description: manifest.windows.product_name,
      authors: 'VOIDCARVE LABS',
      owners: 'VOIDCARVE LABS',
      setupExe: 'Setup.exe',
      setupIcon: path.join(appDir,'resources','installer.ico'),
      skipUpdateIcon: true,
      noMsi: true,
      noDelta: true,
      usePackageJson: false,
      fixUpPaths: false,
      windowsSign: { hookModulePath: hookModule },
    });
  } finally {
    if (previousTemp === undefined) delete process.env.TEMP;
    else process.env.TEMP = previousTemp;
    if (previousTmp === undefined) delete process.env.TMP;
    else process.env.TMP = previousTmp;
  }
  if ((await readdir(work)).includes(path.basename(hookFailureMarker))) throw new Error('Squirrel signing hook failed');
  const entries = await readdir(buildDir);
  const packageFiles = entries.filter(file => /^[A-Za-z0-9][A-Za-z0-9_.-]*-full\.nupkg$/.test(file));
  if (packageFiles.length !== 1 || packageFiles[0] !== `${packageName}-${packageVersion}-full.nupkg`) throw new Error('Squirrel package output rejected');
  const releasePath = path.join(buildDir, 'RELEASES');
  const releases = (await readFile(releasePath, 'utf8')).trim().split(/\r?\n/);
  if (releases.length !== 1) throw new Error('Squirrel release index rejected');
  const [releaseHash, releaseFile, releaseSizeText] = releases[0].split(' ');
  const packagePath = path.join(buildDir, packageFiles[0]);
  const packageStat = await lstat(packagePath);
  if (releaseFile !== packageFiles[0] || !/^[a-f0-9]{40}$/i.test(releaseHash) || Number(releaseSizeText) !== packageStat.size) throw new Error('Squirrel release index mismatch');
  const hash = createHash('sha1');
  for await (const chunk of createReadStream(packagePath)) hash.update(chunk);
  if (hash.digest('hex').toLowerCase() !== releaseHash.toLowerCase()) throw new Error('Squirrel package digest mismatch');

  await invokePowerShell(signScript, 'Verify', configPath, path.join(buildDir, 'Setup.exe'));
  await copyOutput(path.join(buildDir, 'Setup.exe'), output, 'product.exe', manifest.max_artifact_bytes);
  await copyOutput(releasePath, output, 'RELEASES', manifest.max_artifact_bytes);
  await copyOutput(packagePath, output, packageFiles[0], manifest.max_artifact_bytes);
  const appFiles = await walkSignableFiles(appDir);
  for (const file of appFiles) await invokePowerShell(signScript, 'Verify', configPath, file);
}

async function execute(manifestInput, inputZip, outputDir, authorize) {
  const manifest = windowsManifestSchema.parse(manifestInput);
  if (process.platform !== 'win32') throw new Error('Windows native signing host required');
  if (typeof authorize !== 'function') throw new Error('signing authorization callback required');
  const output = path.resolve(outputDir);
  await ensureEmptyDirectory(output);
  const workBase = path.resolve(outputDir, '..');
  await mkdir(workBase, { recursive: true, mode: 0o700 });
  const work = await mkdtemp(path.join(workBase, 'windows-sign-'));
  await chmod(work, 0o700);
  const unpackRoot = path.join(work, 'input');
  const script = path.join(REPOSITORY_ROOT, 'runner', 'windows-sign.ps1');
  const configPath = path.join(work, 'signing-config.json');
  let failureCode = 'input_archive';
  try {
    const archivePath = await snapshotArchive(path.resolve(inputZip), path.join(work, 'input.zip'), manifest.max_artifact_bytes, manifest.input_digest);
    failureCode = 'archive_validation';
    const appDir = await extractInput(archivePath, unpackRoot, manifest);
    failureCode = 'static_verification';
    const executable = path.join(appDir, manifest.windows.executable_name);
    const executableStat = await lstat(executable);
    if (!executableStat.isFile() || executableStat.isSymbolicLink() || !contained(path.resolve(appDir), path.resolve(executable))) throw new Error('approved application executable missing');
    if (await inspectPeArchitecture(executable) !== manifest.architecture) throw new Error('application architecture mismatch');
    await writeFile(configPath, JSON.stringify({
      azure: manifest.azure,
      app_root: appDir,
      allowed_roots: [
        appDir,
        path.join(work, 'builder-output'),
        path.join(work, 'squirrel-output'),
        path.join(work, 'squirrel-temp'),
        path.join(work, 'squirrel-vendor'),
      ],
    }), { flag: 'wx', mode: 0o600 });
    const details = await invokePowerShell(script, 'Inspect', configPath, executable);
    if (normalizeProductVersion(details.product_version) !== normalizeProductVersion(manifest.version)) throw new Error('application version mismatch');
    const icon=path.join(appDir,'resources','installer.ico');
    const iconInfo=await lstat(icon);
    if (!iconInfo.isFile()||iconInfo.isSymbolicLink()||iconInfo.size<6||iconInfo.size>4_000_000) throw new Error('installer icon rejected');
    const iconHeader=(await readFile(icon)).subarray(0,6);
    if(iconHeader.readUInt16LE(0)!==0||iconHeader.readUInt16LE(2)!==1||iconHeader.readUInt16LE(4)<1) throw new Error('installer icon rejected');
    const signable = await walkSignableFiles(appDir);
    if (!signable.includes(executable)) throw new Error('main executable is not a signable file');
    if (manifest.windows.installer === 'squirrel' && !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/.test(manifest.windows.product_name)) {
      throw new Error('Squirrel product name is not package-safe');
    }
    failureCode = 'authorization';
    await authorize();
    failureCode = 'codesign';
    await invokePowerShell(script, 'SignFolder', configPath, appDir);
    for (const file of signable) await invokePowerShell(script, 'Verify', configPath, file);
    const signOne = async file => {
      const absolute = path.resolve(file);
      if (absolute !== path.resolve(executable) && !contained(path.resolve(appDir), absolute) && !contained(path.resolve(work, 'builder-output'), absolute)) {
        throw new Error('signer requested an out-of-scope file');
      }
      const extension = path.extname(absolute).toLowerCase();
      if (!SIGNABLE_EXTENSIONS.has(extension)) throw new Error('signer requested a non-PE file');
      const metadata = await lstat(absolute);
      if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error('signer requested an invalid file');
      try {
        await invokePowerShell(script, 'Verify', configPath, absolute);
      } catch {
        await invokePowerShell(script, 'Sign', configPath, absolute);
      }
    };
    if (manifest.windows.installer === 'nsis') {
      await signNsis(manifest, appDir, work, output, signOne, script, configPath);
    } else {
      await signSquirrel(manifest, appDir, work, output, script, configPath);
    }
    failureCode = 'signature_verification';
    const productName = `${manifest.windows.product_name}-${manifest.architecture}`;
    const files = await collectReportFiles(output, manifest, productName);
    if (files.reduce((sum, item) => sum + item.size, 0) > manifest.max_artifact_bytes) throw new Error('signed outputs exceed approved size');
    const report = windowsVerificationSchema.parse({
      schema_version: 1,
      request_id: manifest.request_id,
      generation: manifest.generation,
      stage: manifest.stage,
      input_digest: manifest.input_digest,
      recipe_sha: manifest.recipe_sha,
      policy_digest: manifest.policy_digest,
      bundle_id: manifest.bundle_id,
      version: manifest.version,
      architecture: manifest.architecture,
      subject: SUBJECT,
      authenticode_verified: true,
      timestamp_verified: true,
      nested_signatures_verified: true,
      files,
    });
    await writeFile(path.join(output, 'verification.json'), JSON.stringify(report), { flag: 'wx', mode: 0o600 });
    return report;
  } catch (error) {
    await rm(output, { recursive: true, force: true });
    await mkdir(output, { recursive: true, mode: 0o700 });
    throw error instanceof RunnerFailure ? error : new RunnerFailure(failureCode);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

export async function executeWindows(manifest, inputZip, outputDir, authorize) {
  try {
    return windowsVerificationSchema.parse(await execute(manifest, inputZip, outputDir, authorize));
  } catch (error) {
    if (error instanceof RunnerFailure) throw new Error(`Windows signing operation failed: ${error.code}`);
    throw new Error('Windows signing operation failed');
  }
}
