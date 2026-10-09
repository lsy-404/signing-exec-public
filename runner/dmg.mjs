import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, mkdtemp, readFile, readdir, readlink, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { credentialsSchema, manifestSchema, verificationSchema } from './contract.mjs';
import { command, fileSha256, identityHash, inspectBundle, keychainSearch, signingRequirement, snapshotArchive } from './macos-sign.mjs';

async function unpack(mode, archive, target, manifest) {
  const script = fileURLToPath(new URL('./dmg-unpack.py',import.meta.url));
  await command(process.env.PYTHON || 'python3',[script,JSON.stringify({
    mode,max_bytes:manifest.max_artifact_bytes,max_unpacked_bytes:manifest.max_unpacked_bytes,bundle_name:manifest.bundle_name,
  }),archive,target]);
}

async function mount(image, directory, readOnly = false) {
  await mkdir(directory,{mode:0o700});
  await command('/usr/bin/hdiutil',['attach',...(readOnly?['-readonly']:[]),'-nobrowse','-noautoopen','-owners','off','-mountpoint',directory,image]);
}

async function layout(directory, manifest) {
  const entries = await readdir(directory,{withFileTypes:true});
  const allowed = new Set([manifest.bundle_name,'Applications','.background','.background.tiff','.DS_Store','.VolumeIcon.icns']);
  if (entries.some(entry=>!allowed.has(entry.name)) || !entries.some(entry=>entry.name===manifest.bundle_name&&entry.isDirectory())) throw new Error('disk image layout rejected');
  for (const entry of entries) {
    if (entry.isSymbolicLink() && (entry.name!=='Applications' || await readlink(path.join(directory,entry.name))!=='/Applications')) throw new Error('disk image link rejected');
    if (entry.name!==manifest.bundle_name && entry.name!=='Applications' && !entry.isFile() && !(entry.name==='.background'&&entry.isDirectory())) throw new Error('disk image layout rejected');
  }
}

async function verifyImage(image, manifest) {
  await command('/usr/bin/codesign',['--verify','--strict','-R',signingRequirement(manifest.team_id),'--verbose=2',image]);
  const details = await command('/usr/bin/codesign',['-dv','--verbose=4',image]);
  const text = details.stdout+'\n'+details.stderr;
  if (text.match(/^TeamIdentifier=(.+)$/m)?.[1]!==manifest.team_id || !text.match(/^Timestamp=(?!none$).+/m)) throw new Error('disk image signature mismatch');
}

async function keychainFor(credentials, work, teamId) {
  const keychain = path.join(work,'signing.keychain-db');
  const password = randomBytes(32).toString('base64url');
  const certificate = path.join(work,'certificate.p12');
  await writeFile(certificate,Buffer.from(credentials.certificate_p12,'base64'),{mode:0o600,flag:'wx'});
  await command('/usr/bin/security',['create-keychain','-p',password,keychain]);
  try {
    await command('/usr/bin/security',['set-keychain-settings','-lut','300',keychain]);
    await command('/usr/bin/security',['unlock-keychain','-p',password,keychain]);
    await command('/usr/bin/security',['import',fileURLToPath(new URL('./certificates/developer-id-g2.cer',import.meta.url)),'-k',keychain,'-T','/usr/bin/codesign']);
    await command('/usr/bin/security',['import',certificate,'-k',keychain,'-P',credentials.certificate_password,'-T','/usr/bin/codesign']);
    await command('/usr/bin/security',['set-key-partition-list','-S','apple-tool:,apple:,codesign:','-s','-k',password,keychain]);
    await keychainSearch(keychain,true);
    return {keychain,identity:await identityHash(keychain,teamId)};
  } catch {
    await keychainSearch(keychain,false);
    await command('/usr/bin/security',['delete-keychain',keychain]);
    throw new Error('disk image signing identity unavailable');
  }
}

export async function executeDmg(rawManifest,inputArchivePath,outputDir,credentialsProvider,templateArchivePath) {
  const manifest = manifestSchema.parse(rawManifest);
  if (process.platform!=='darwin' || !['dmg_sign','dmg_finalize'].includes(manifest.stage)) throw new Error('invalid disk image signing host or stage');
  const signing = manifest.stage==='dmg_sign';
  if (signing ? typeof credentialsProvider!=='function'||!templateArchivePath : credentialsProvider!==undefined) throw new Error('invalid disk image credentials provider');
  await mkdir(outputDir,{recursive:true,mode:0o700});
  if ((await readdir(outputDir)).length) throw new Error('output directory must be empty');
  const work = await mkdtemp(path.join(os.tmpdir(),'dmg-sign-'));
  await chmod(work,0o700);
  let attached;
  let keychain;
  let phase = 'input';
  try {
    const input = await snapshotArchive(inputArchivePath,path.join(work,'input.zip'),manifest.max_artifact_bytes,manifest.input_digest);
    let image;
    let asarVerified;
    if (signing) {
      const product = path.join(work,'product.zip');
      await unpack('product',input,product,manifest);
      const extract = path.join(work,'extract');
      await mkdir(extract,{mode:0o700});
      await command('/usr/bin/ditto',['-x','-k',product,extract]);
      const app = path.join(extract,manifest.bundle_name);
      phase = 'app-verification';
      asarVerified = (await inspectBundle(app,manifest,work,true)).asarVerified;
      await command('/usr/bin/xcrun',['stapler','validate',app]);
      await command('/usr/sbin/spctl',['--assess','--type','execute','--verbose=2',app]);
      const templateZip = await snapshotArchive(templateArchivePath,path.join(work,'template.zip'),manifest.max_artifact_bytes,manifest.template_digest);
      const template = path.join(work,'template.dmg');
      await unpack('template',templateZip,template,manifest);
      phase = 'image-layout';
      image = path.join(work,'signed.dmg');
      const writable = path.join(work,'writable.dmg');
      await command('/usr/bin/hdiutil',['convert',template,'-format','UDRW','-o',writable]);
      if ((await lstat(writable)).size>manifest.max_unpacked_bytes) throw new Error('disk image exceeds approved limit');
      attached = path.join(work,'mount');
      await mount(writable,attached);
      await layout(attached,manifest);
      await inspectBundle(path.join(attached,manifest.bundle_name),manifest,work,false);
      await rm(path.join(attached,manifest.bundle_name),{recursive:true});
      await command('/usr/bin/ditto',[app,path.join(attached,manifest.bundle_name)]);
      await inspectBundle(path.join(attached,manifest.bundle_name),manifest,work,true);
      await command('/usr/bin/hdiutil',['detach',attached]);
      attached = undefined;
      await command('/usr/bin/hdiutil',['convert',writable,'-format','UDZO','-o',image]);
      phase = 'credentials';
      const credentials = credentialsSchema.parse(await credentialsProvider());
      const identity = await keychainFor(credentials,work,manifest.team_id);
      keychain = identity.keychain;
      phase = 'image-signing';
      await command('/usr/bin/codesign',['--force','--sign',identity.identity,'--keychain',keychain,'--timestamp',image]);
      await verifyImage(image,manifest);
      const keyFile = path.join(work,'notary.p8');
      await writeFile(keyFile,credentials.notarization.private_key,{mode:0o600,flag:'wx'});
      phase = 'notarization-submit';
      const hash = await fileSha256(image);
      const result = await command('/usr/bin/xcrun',['notarytool','submit',image,'--key',keyFile,'--key-id',credentials.notarization.key_id,'--issuer',credentials.notarization.issuer_id,'--output-format','json']);
      const id = JSON.parse(result.stdout).id;
      return await output(image,outputDir,manifest,asarVerified,id,hash,false);
    }
    image = path.join(work,'product.dmg');
    await unpack('signed',input,image,manifest);
    phase = 'image-verification';
    if (await fileSha256(image)!==manifest.notary_archive_sha256) throw new Error('disk image notarization receipt mismatch');
    await verifyImage(image,manifest);
    phase = 'stapling';
    await command('/usr/bin/xcrun',['stapler','staple',image]);
    await command('/usr/bin/xcrun',['stapler','validate',image]);
    await verifyImage(image,manifest);
    await command('/usr/sbin/spctl',['--assess','--type','open','--context','context:primary-signature','--verbose=2',image]);
    attached = path.join(work,'mount');
    await mount(image,attached,true);
    await layout(attached,manifest);
    const app = path.join(attached,manifest.bundle_name);
    asarVerified = (await inspectBundle(app,manifest,work,true)).asarVerified;
    await command('/usr/bin/xcrun',['stapler','validate',app]);
    await command('/usr/sbin/spctl',['--assess','--type','execute','--verbose=2',app]);
    await command('/usr/bin/hdiutil',['detach',attached]);
    attached = undefined;
    return await output(image,outputDir,manifest,asarVerified,manifest.notarization_id,manifest.notary_archive_sha256,true);
  } catch {
    await rm(outputDir,{recursive:true,force:true});
    await mkdir(outputDir,{mode:0o700});
    throw new Error(`disk image operation failed: ${phase}`);
  } finally {
    let failed = false;
    if (attached) try { await command('/usr/bin/hdiutil',['detach',attached]); } catch { failed = true; }
    if (keychain) {
      try { await keychainSearch(keychain,false); } catch { failed = true; }
      try { await command('/usr/bin/security',['delete-keychain',keychain]); } catch { failed = true; }
    }
    if (!attached || !failed) await rm(work,{recursive:true,force:true});
    if (failed) {
      await rm(outputDir,{recursive:true,force:true});
      throw new Error('disk image cleanup failed');
    }
  }
}

async function output(image,directory,manifest,asarVerified,notaryId,notaryHash,finalized) {
  const name = finalized?'product.dmg':'signed.dmg';
  const size = (await lstat(image)).size;
  if (size>manifest.max_artifact_bytes) throw new Error('disk image exceeds approved limit');
  const report = verificationSchema.parse({
    schema_version:1,request_id:manifest.request_id,generation:manifest.generation,stage:manifest.stage,
    input_digest:manifest.input_digest,recipe_sha:manifest.recipe_sha,policy_digest:manifest.policy_digest,
    team_id:manifest.team_id,bundle_id:manifest.bundle_id,version:manifest.version,architecture:manifest.architecture,
    codesign_verified:true,timestamp_verified:true,asar_integrity_verified:asarVerified,
    notarization_id:notaryId,notarization_status:finalized?'Accepted':'Submitted',notary_archive_sha256:notaryHash,
    gatekeeper_verified:finalized,staple_verified:finalized,files:[{path:name,size,sha256:await fileSha256(image)}],
  });
  await copyFile(image,path.join(directory,name),constants.COPYFILE_EXCL);
  await chmod(path.join(directory,name),0o600);
  await writeFile(path.join(directory,'verification.json'),JSON.stringify(report),{mode:0o600,flag:'wx'});
  return report;
}
