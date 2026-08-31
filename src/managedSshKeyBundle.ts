export const MANAGED_SSH_KEY_BUNDLE_MAGIC = "NCTMKRAW";
export const MANAGED_SSH_KEY_BUNDLE_VERSION = 1;
export const MANAGED_SSH_KEY_BUNDLE_HEADER_BYTES = 28;

export const MANAGED_SSH_KEY_PRIVATE_KEY_MAX_BYTES = 4 * 1024 * 1024;
export const MANAGED_SSH_KEY_PUBLIC_KEY_MAX_BYTES = 1024 * 1024;
export const MANAGED_SSH_KEY_CERTIFICATE_MAX_BYTES = 1024 * 1024;
export const MANAGED_SSH_KEY_PASSPHRASE_MAX_BYTES = 64 * 1024;

const FLAG_PUBLIC_KEY = 1 << 0;
const FLAG_CERTIFICATE = 1 << 1;
const FLAG_PASSPHRASE = 1 << 2;

export type ManagedSshKeyBundleBytes = {
  privateKey: Uint8Array;
  publicKey?: Uint8Array;
  certificate?: Uint8Array;
  passphrase?: Uint8Array;
};

const validateField = (
  value: Uint8Array | undefined,
  maximum: number,
  required: boolean,
): number => {
  const length = value?.byteLength ?? 0;
  if ((required && length === 0) || length > maximum) {
    throw new Error("MANAGED_SSH_KEY_BUNDLE_INVALID");
  }
  return length;
};

/**
 * Builds the fixed raw-IPC envelope consumed by `stage_managed_ssh_key_bundle`.
 * All lengths are unsigned 32-bit big-endian values. Secret fields never become
 * object keys or string values in an ordinary Tauri invoke payload.
 */
export const encodeManagedSshKeyBundleEnvelope = (
  bundle: ManagedSshKeyBundleBytes,
): Uint8Array => {
  const privateKeyLength = validateField(
    bundle.privateKey,
    MANAGED_SSH_KEY_PRIVATE_KEY_MAX_BYTES,
    true,
  );
  const publicKeyLength = validateField(
    bundle.publicKey,
    MANAGED_SSH_KEY_PUBLIC_KEY_MAX_BYTES,
    false,
  );
  const certificateLength = validateField(
    bundle.certificate,
    MANAGED_SSH_KEY_CERTIFICATE_MAX_BYTES,
    false,
  );
  const passphraseLength = validateField(
    bundle.passphrase,
    MANAGED_SSH_KEY_PASSPHRASE_MAX_BYTES,
    false,
  );
  const payloadLength = privateKeyLength
    + publicKeyLength
    + certificateLength
    + passphraseLength;
  const envelope = new Uint8Array(MANAGED_SSH_KEY_BUNDLE_HEADER_BYTES + payloadLength);
  const view = new DataView(envelope.buffer, envelope.byteOffset, envelope.byteLength);

  envelope.set(new TextEncoder().encode(MANAGED_SSH_KEY_BUNDLE_MAGIC), 0);
  envelope[8] = MANAGED_SSH_KEY_BUNDLE_VERSION;
  envelope[9] = (publicKeyLength > 0 ? FLAG_PUBLIC_KEY : 0)
    | (certificateLength > 0 ? FLAG_CERTIFICATE : 0)
    | (passphraseLength > 0 ? FLAG_PASSPHRASE : 0);
  // Bytes 10..11 are reserved and intentionally remain zero.
  view.setUint32(12, privateKeyLength);
  view.setUint32(16, publicKeyLength);
  view.setUint32(20, certificateLength);
  view.setUint32(24, passphraseLength);

  let offset = MANAGED_SSH_KEY_BUNDLE_HEADER_BYTES;
  for (const field of [
    bundle.privateKey,
    bundle.publicKey,
    bundle.certificate,
    bundle.passphrase,
  ]) {
    if (field && field.byteLength > 0) {
      envelope.set(field, offset);
      offset += field.byteLength;
    }
  }
  return envelope;
};

/**
 * Transfers ownership of all supplied byte arrays for one staging attempt.
 * Inputs and the encoded envelope are cleared whether staging succeeds or
 * fails. Callers must not reuse the arrays after calling this function.
 */
export const withZeroizedManagedSshKeyBundle = async <T>(
  bundle: ManagedSshKeyBundleBytes,
  stage: (envelope: Uint8Array) => Promise<T>,
): Promise<T> => {
  let envelope: Uint8Array | undefined;
  try {
    envelope = encodeManagedSshKeyBundleEnvelope(bundle);
    return await stage(envelope);
  } finally {
    envelope?.fill(0);
    bundle.privateKey.fill(0);
    bundle.publicKey?.fill(0);
    bundle.certificate?.fill(0);
    bundle.passphrase?.fill(0);
  }
};
