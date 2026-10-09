import { z } from 'zod';

export const sha256 = z.string().regex(/^[a-f0-9]{64}$/);
export const archiveDigest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
export const commitSha = z.string().regex(/^[a-f0-9]{40}$/);
export const executableName = z.string().regex(/^[\p{L}\p{M}\p{N}_.-][\p{L}\p{M}\p{N} _.-]*$/u)
  .refine(value => value !== '.' && value !== '..' && value === value.normalize('NFC') && new TextEncoder().encode(value).length <= 255);
export const bundleName = executableName.refine(value => /^[\p{L}\p{N}][\p{L}\p{M}\p{N} _.-]*\.app$/u.test(value));
export const stageSchema = z.enum(['sign', 'finalize', 'dmg_sign', 'dmg_finalize']);
export const sourceMetadataSchema = z.object({
  source_sha: commitSha,
  version: z.string().regex(/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/).max(64),
  bundle_id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$/),
  architecture: z.enum(['arm64', 'x64', 'universal']),
}).strict();
export const manifestSchema = z.object({
  schema_version: z.literal(1),
  request_id: z.uuid(),
  generation: z.number().int().positive(),
  stage: stageSchema,
  project_id: z.string().regex(/^[a-z][a-z0-9-]{0,63}$/),
  version: z.string().regex(/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/).max(64),
  source_sha: commitSha,
  input_digest: archiveDigest,
  recipe_sha: commitSha,
  policy_digest: archiveDigest,
  team_id: z.string().regex(/^[A-Z0-9]{10}$/),
  bundle_id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$/),
  bundle_name: bundleName,
  architecture: z.enum(['arm64', 'x64', 'universal']),
  profile: z.enum(['native', 'electron']),
  harden_electron_fuses: z.boolean().default(false),
  max_artifact_bytes: z.number().int().positive().max(2_000_000_000),
  max_unpacked_bytes: z.number().int().positive().max(8_000_000_000),
  notarization_id: z.uuid().optional(),
  notary_archive_sha256: sha256.optional(),
  template_digest: archiveDigest.optional(),
}).strict().refine(value => !value.stage.endsWith('finalize') || Boolean(value.notarization_id && value.notary_archive_sha256))
  .refine(value => value.stage !== 'dmg_sign' || Boolean(value.template_digest));

export const notarizationCredentialsSchema = z.object({
  key_id: z.string().regex(/^[A-Z0-9]{10}$/),
  issuer_id: z.uuid(),
  private_key: z.string().min(100).max(10_000),
}).strict();

export const credentialsSchema = z.object({
  certificate_p12: z.string().regex(/^[A-Za-z0-9+/]+={0,2}$/).max(40_000),
  certificate_password: z.string().min(1).max(512),
  notarization: notarizationCredentialsSchema,
}).strict();

export const verificationSchema = z.object({
  schema_version: z.literal(1),
  request_id: z.uuid(),
  generation: z.number().int().positive(),
  stage: stageSchema,
  input_digest: archiveDigest,
  recipe_sha: commitSha,
  policy_digest: archiveDigest,
  team_id: z.string().regex(/^[A-Z0-9]{10}$/),
  bundle_id: z.string().min(1).max(255),
  version: z.string().min(1).max(64),
  architecture: z.enum(['arm64', 'x64', 'universal']),
  codesign_verified: z.literal(true),
  timestamp_verified: z.literal(true),
  asar_integrity_verified: z.boolean(),
  notarization_id: z.uuid(),
  notarization_status: z.enum(['Submitted', 'Accepted']),
  notary_archive_sha256: sha256,
  gatekeeper_verified: z.boolean(),
  staple_verified: z.boolean(),
  files: z.array(z.object({
    path: z.enum(['signed.tar.gz', 'product.zip', 'signed.dmg', 'product.dmg']),
    size: z.number().int().positive(),
    sha256,
  }).strict()).length(1),
}).strict();
