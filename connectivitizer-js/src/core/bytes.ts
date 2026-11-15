// Small byte helpers. Written out here rather than taken from the runtime (Buffer, atob,
// TextDecoder) so that the core behaves the same in Node.js and in React Native.

export function concat(...parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) {
    length += part.length;
  }
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

export function utf8Encode(text: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < text.length; i++) {
    let code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdfff) {
      const low = code <= 0xdbff && i + 1 < text.length ? text.charCodeAt(i + 1) : 0;
      if (low >= 0xdc00 && low <= 0xdfff) {
        code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
        i++;
      } else {
        code = 0xfffd; // half of a pair on its own is not a character
      }
    }
    if (code < 0x80) {
      out.push(code);
    } else if (code < 0x800) {
      out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0x10000) {
      out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      out.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    }
  }
  return Uint8Array.from(out);
}

/** Decodes UTF-8; bytes that are not valid UTF-8 become U+FFFD. */
export function utf8Decode(bytes: Uint8Array): string {
  let result = '';
  let chunk: number[] = [];
  const flush = () => {
    result += String.fromCharCode(...chunk);
    chunk = [];
  };
  for (let i = 0; i < bytes.length; ) {
    const first = bytes[i++];
    let code: number;
    if (first < 0x80) {
      code = first;
    } else {
      const extra = first >= 0xf0 && first < 0xf8 ? 3 : first >= 0xe0 ? 2 : first >= 0xc0 ? 1 : -1;
      if (extra < 0 || first >= 0xf8 || i + extra > bytes.length) {
        code = 0xfffd;
      } else {
        code = first & (0x3f >> extra);
        let valid = true;
        for (let k = 0; k < extra; k++) {
          const next = bytes[i + k];
          if ((next & 0xc0) !== 0x80) {
            valid = false;
            break;
          }
          code = (code << 6) | (next & 0x3f);
        }
        if (valid) {
          i += extra;
        } else {
          code = 0xfffd;
        }
      }
    }
    if (code >= 0x10000) {
      code -= 0x10000;
      chunk.push(0xd800 + (code >> 10), 0xdc00 + (code & 0x3ff));
    } else {
      chunk.push(code);
    }
    if (chunk.length >= 4096) {
      flush();
    }
  }
  flush();
  return result;
}

const HEX = '0123456789abcdef';

export function toHex(bytes: Uint8Array): string {
  let result = '';
  for (const byte of bytes) {
    result += HEX[byte >> 4] + HEX[byte & 15];
  }
  return result;
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
    throw new Error('Not a hex string.');
  }
  const result = new Uint8Array(hex.length / 2);
  for (let i = 0; i < result.length; i++) {
    result[i] = parseInt(hex.substring(2 * i, 2 * i + 2), 16);
  }
  return result;
}

const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64_URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function encode64(bytes: Uint8Array, alphabet: string, pad: boolean): string {
  let result = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
    result += alphabet[a >> 2] + alphabet[((a & 3) << 4) | (b >> 4)];
    result += i + 1 < bytes.length ? alphabet[((b & 15) << 2) | (c >> 6)] : pad ? '=' : '';
    result += i + 2 < bytes.length ? alphabet[c & 63] : pad ? '=' : '';
  }
  return result;
}

/** Decodes base64 and base64url alike, with or without padding. Throws on anything else. */
export function base64Decode(text: string): Uint8Array {
  const clean = text.replace(/=+$/, '');
  if (clean.length % 4 === 1) {
    throw new Error('Not a base64 string.');
  }
  const result = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let bits = 0;
  let count = 0;
  let offset = 0;
  for (let i = 0; i < clean.length; i++) {
    const char = clean[i];
    let value = BASE64.indexOf(char);
    if (value < 0) {
      value = char === '-' ? 62 : char === '_' ? 63 : -1;
    }
    if (value < 0) {
      throw new Error('Not a base64 string.');
    }
    bits = (bits << 6) | value;
    count += 6;
    if (count >= 8) {
      count -= 8;
      result[offset++] = (bits >> count) & 0xff;
    }
  }
  return result;
}

export const base64Encode = (bytes: Uint8Array): string => encode64(bytes, BASE64, true);

/** Base64url without padding, as used in tokens and keys. */
export const base64UrlEncode = (bytes: Uint8Array): string => encode64(bytes, BASE64_URL, false);

/** Compares without stopping at the first difference, so timing does not tell where two secrets differ. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let difference = 0;
  for (let i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }
  return difference === 0;
}

export function writeUint16(target: Uint8Array, offset: number, value: number): void {
  target[offset] = (value >>> 8) & 0xff;
  target[offset + 1] = value & 0xff;
}

export function writeUint32(target: Uint8Array, offset: number, value: number): void {
  target[offset] = (value >>> 24) & 0xff;
  target[offset + 1] = (value >>> 16) & 0xff;
  target[offset + 2] = (value >>> 8) & 0xff;
  target[offset + 3] = value & 0xff;
}

export const readUint16 = (source: Uint8Array, offset: number): number => (source[offset] << 8) | source[offset + 1];

export const readUint32 = (source: Uint8Array, offset: number): number =>
  ((source[offset] << 24) | (source[offset + 1] << 16) | (source[offset + 2] << 8) | source[offset + 3]) >>> 0;
