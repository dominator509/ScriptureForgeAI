'use strict';

const fs = require('node:fs');
const path = require('node:path');

const MAX_INPUT_BYTES = 512 * 1024;
const SAFE_TYPES = Object.freeze([
  'bmp',
  'gif',
  'jpg',
  'ktx',
  'png',
  'psd',
  'svg',
  'tiff',
  'webp',
]);

const disabledTypes = new Set();
let disabledFS = false;
let concurrency = 100;

function imageSize(input, callback) {
  if (input instanceof Uint8Array) {
    return lookup(toBuffer(input));
  }

  if (typeof input !== 'string' || disabledFS) {
    throw new TypeError('invalid invocation. input should be a Uint8Array');
  }

  const filepath = path.resolve(input);
  if (typeof callback === 'function') {
    readFileAsync(filepath)
      .then((data) => process.nextTick(callback, null, lookup(data)))
      .catch((error) => process.nextTick(callback, error));
    return undefined;
  }

  return lookup(readFileSync(filepath));
}

function lookup(input) {
  const type = detectType(input);
  if (!type || !SAFE_TYPES.includes(type)) {
    throw new TypeError(`unsupported file type: ${type ?? 'unknown'}`);
  }
  if (disabledTypes.has(type)) {
    throw new TypeError(`disabled file type: ${type}`);
  }

  const dimensions = parsers[type](input);
  return {
    ...dimensions,
    type,
  };
}

function detectType(input) {
  if (input.length >= 8 && hex(input, 0, 8) === '89504e470d0a1a0a') return 'png';
  if (input.length >= 6 && (ascii(input, 0, 'GIF87a') || ascii(input, 0, 'GIF89a'))) return 'gif';
  if (input.length >= 2 && input[0] === 0xff && input[1] === 0xd8) return 'jpg';
  if (input.length >= 2 && input[0] === 0x42 && input[1] === 0x4d) return 'bmp';
  if (input.length >= 4 && ascii(input, 0, '8BPS')) return 'psd';
  if (input.length >= 12 && ascii(input, 0, 'RIFF') && ascii(input, 8, 'WEBP')) return 'webp';
  if (input.length >= 4 && ((input[0] === 0x49 && input[1] === 0x49 && input[2] === 0x2a && input[3] === 0x00) || (input[0] === 0x4d && input[1] === 0x4d && input[2] === 0x00 && input[3] === 0x2a))) return 'tiff';
  if (isKtx(input)) return 'ktx';

  const svgPrefix = input.subarray(0, Math.min(input.length, 1024)).toString('utf8').replace(/^\uFEFF/, '').trimStart();
  if (/^(?:<\?xml\b[\s\S]*?>\s*)?<svg\b/i.test(svgPrefix)) return 'svg';
  return undefined;
}

function parsePng(input) {
  requireLength(input, 24, 'PNG');
  return dimensions(readUInt32BE(input, 16), readUInt32BE(input, 20));
}

function parseGif(input) {
  requireLength(input, 10, 'GIF');
  return dimensions(readUInt16LE(input, 6), readUInt16LE(input, 8));
}

function parseJpeg(input) {
  requireLength(input, 4, 'JPEG');
  let offset = 2;
  while (offset < input.length) {
    while (offset < input.length && input[offset] !== 0xff) offset += 1;
    while (offset < input.length && input[offset] === 0xff) offset += 1;
    if (offset >= input.length) break;

    const marker = input[offset++];
    if (marker === 0x00) continue;
    if (marker === 0xd9 || marker === 0xda) break;
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;

    requireLength(input, offset + 2, 'JPEG segment');
    const segmentLength = readUInt16BE(input, offset);
    if (segmentLength < 2 || offset + segmentLength > input.length) {
      throw new TypeError('invalid JPEG segment length');
    }

    if (isJpegStartOfFrame(marker)) {
      requireLength(input, offset + 7, 'JPEG frame');
      return dimensions(readUInt16BE(input, offset + 5), readUInt16BE(input, offset + 3));
    }
    offset += segmentLength;
  }
  throw new TypeError('JPEG dimensions not found');
}

function parseBmp(input) {
  requireLength(input, 26, 'BMP');
  const width = input.readInt32LE(18);
  const height = Math.abs(input.readInt32LE(22));
  return dimensions(width, height);
}

function parsePsd(input) {
  requireLength(input, 26, 'PSD');
  return dimensions(readUInt32BE(input, 18), readUInt32BE(input, 14));
}

function parseWebp(input) {
  requireLength(input, 30, 'WebP');
  const chunk = input.subarray(12, 16).toString('ascii');
  if (chunk === 'VP8X') {
    return dimensions(readUInt24LE(input, 24) + 1, readUInt24LE(input, 27) + 1);
  }
  if (chunk === 'VP8L') {
    if (input[20] !== 0x2f) throw new TypeError('invalid WebP lossless header');
    const width = 1 + (input[21] | ((input[22] & 0x3f) << 8));
    const height = 1 + ((input[22] >> 6) | (input[23] << 2) | ((input[24] & 0x0f) << 10));
    return dimensions(width, height);
  }
  if (chunk === 'VP8 ') {
    requireLength(input, 32, 'WebP lossy frame');
    if (input[23] !== 0x9d || input[24] !== 0x01 || input[25] !== 0x2a) {
      throw new TypeError('invalid WebP lossy frame');
    }
    return dimensions(readUInt16LE(input, 26) & 0x3fff, readUInt16LE(input, 28) & 0x3fff);
  }
  throw new TypeError(`unsupported WebP chunk: ${chunk}`);
}

function parseSvg(input) {
  const source = input.subarray(0, MAX_INPUT_BYTES).toString('utf8');
  const root = source.match(/<svg\b[^>]*>/i)?.[0];
  if (!root) throw new TypeError('SVG root element not found');

  const width = parseSvgLength(attribute(root, 'width'));
  const height = parseSvgLength(attribute(root, 'height'));
  if (width !== undefined && height !== undefined) return dimensions(width, height);

  const viewBox = attribute(root, 'viewBox')?.trim().split(/[\s,]+/).map(Number);
  if (viewBox?.length === 4 && viewBox.every(Number.isFinite) && viewBox[2] > 0 && viewBox[3] > 0) {
    return dimensions(viewBox[2], viewBox[3]);
  }
  throw new TypeError('SVG dimensions not found');
}

function parseKtx(input) {
  requireLength(input, 44, 'KTX');
  const isKtx2 = input[5] === 0x32;
  if (isKtx2) {
    return dimensions(readUInt32LE(input, 20), readUInt32LE(input, 24));
  }
  const endianness = readUInt32LE(input, 12);
  if (endianness === 0x04030201) return dimensions(readUInt32LE(input, 36), readUInt32LE(input, 40));
  if (endianness === 0x01020304) return dimensions(readUInt32BE(input, 36), readUInt32BE(input, 40));
  throw new TypeError('invalid KTX endianness');
}

function parseTiff(input) {
  requireLength(input, 8, 'TIFF');
  const littleEndian = input[0] === 0x49;
  const read16 = littleEndian ? readUInt16LE : readUInt16BE;
  const read32 = littleEndian ? readUInt32LE : readUInt32BE;
  const ifdOffset = read32(input, 4);
  requireRange(input, ifdOffset, 2, 'TIFF IFD');
  const entryCount = read16(input, ifdOffset);
  if (entryCount > 4096) throw new TypeError('TIFF IFD entry count exceeds limit');
  let width;
  let height;
  for (let index = 0; index < entryCount; index += 1) {
    const entry = ifdOffset + 2 + index * 12;
    requireRange(input, entry, 12, 'TIFF entry');
    const tag = read16(input, entry);
    if (tag !== 256 && tag !== 257) continue;
    const value = readTiffScalar(input, entry, read16, read32, littleEndian);
    if (tag === 256) width = value;
    if (tag === 257) height = value;
  }
  return dimensions(width, height);
}

function readTiffScalar(input, entry, read16, read32, littleEndian) {
  const type = read16(input, entry + 2);
  const count = read32(input, entry + 4);
  if (count < 1 || count > 4096) throw new TypeError('TIFF value count exceeds limit');
  const typeSize = { 1: 1, 3: 2, 4: 4 }[type];
  if (!typeSize) throw new TypeError('unsupported TIFF dimension type');
  const byteLength = typeSize * count;
  const valueOffset = byteLength <= 4 ? entry + 8 : read32(input, entry + 8);
  requireRange(input, valueOffset, typeSize, 'TIFF dimension value');
  if (type === 1) return input[valueOffset];
  if (type === 3) return littleEndian ? read16(input, valueOffset) : read16(input, valueOffset);
  return read32(input, valueOffset);
}

function isKtx(input) {
  return input.length >= 12 && bytesEqual(input, 0, [0xab, 0x4b, 0x54, 0x58, 0x20, 0x31, 0x31, 0xbb, 0x0d, 0x0a, 0x1a, 0x0a])
    || input.length >= 12 && bytesEqual(input, 0, [0xab, 0x4b, 0x54, 0x58, 0x20, 0x32, 0x30, 0xbb, 0x0d, 0x0a, 0x1a, 0x0a]);
}

function isJpegStartOfFrame(marker) {
  return (marker >= 0xc0 && marker <= 0xc3) || (marker >= 0xc5 && marker <= 0xc7) || (marker >= 0xc9 && marker <= 0xcb) || (marker >= 0xcd && marker <= 0xcf);
}

function attribute(root, name) {
  return root.match(new RegExp(`\\b${name}\\s*=\\s*(["'])(.*?)\\1`, 'i'))?.[2];
}

function parseSvgLength(value) {
  if (value === undefined || /%/.test(value)) return undefined;
  const match = value.match(/^\s*([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?)\s*(?:px|pt|pc|cm|mm|in)?\s*$/i);
  if (!match) return undefined;
  const number = Number(match[1]);
  return Number.isFinite(number) && number > 0 ? number : undefined;
}

function readFileSync(filepath) {
  const descriptor = fs.openSync(filepath, 'r');
  try {
    const size = fs.fstatSync(descriptor).size;
    if (size <= 0) throw new Error('Empty file');
    const input = Buffer.allocUnsafe(Math.min(size, MAX_INPUT_BYTES));
    fs.readSync(descriptor, input, 0, input.length, 0);
    return input;
  } finally {
    fs.closeSync(descriptor);
  }
}

async function readFileAsync(filepath) {
  const handle = await fs.promises.open(filepath, 'r');
  try {
    const size = (await handle.stat()).size;
    if (size <= 0) throw new Error('Empty file');
    const input = Buffer.allocUnsafe(Math.min(size, MAX_INPUT_BYTES));
    await handle.read(input, 0, input.length, 0);
    return input;
  } finally {
    await handle.close();
  }
}

function toBuffer(input) {
  return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
}

function ascii(input, offset, value) {
  if (offset + value.length > input.length) return false;
  return input.subarray(offset, offset + value.length).toString('ascii') === value;
}

function hex(input, offset, length) {
  return input.subarray(offset, offset + length).toString('hex');
}

function bytesEqual(input, offset, bytes) {
  if (offset + bytes.length > input.length) return false;
  return bytes.every((value, index) => input[offset + index] === value);
}

function readUInt16LE(input, offset) { return input.readUInt16LE(offset); }
function readUInt16BE(input, offset) { return input.readUInt16BE(offset); }
function readUInt32LE(input, offset) { return input.readUInt32LE(offset); }
function readUInt32BE(input, offset) { return input.readUInt32BE(offset); }
function readUInt24LE(input, offset) { return input[offset] | (input[offset + 1] << 8) | (input[offset + 2] << 16); }

function requireLength(input, length, label) {
  if (input.length < length) throw new TypeError(`truncated ${label} header`);
}

function requireRange(input, offset, length, label) {
  if (!Number.isInteger(offset) || offset < 0 || length < 0 || offset + length > input.length) {
    throw new TypeError(`invalid ${label} bounds`);
  }
}

function dimensions(width, height) {
  if (!Number.isFinite(width) || !Number.isFinite(height) || width <= 0 || height <= 0 || width > 0x7fffffff || height > 0x7fffffff) {
    throw new TypeError('invalid image dimensions');
  }
  return { width, height };
}

imageSize.imageSize = imageSize;
imageSize.default = imageSize;
imageSize.types = [...SAFE_TYPES];
imageSize.disableFS = (value) => { disabledFS = Boolean(value); };
imageSize.disableTypes = (types) => {
  disabledTypes.clear();
  for (const type of types ?? []) disabledTypes.add(String(type).toLowerCase());
};
imageSize.setConcurrency = (value) => {
  if (!Number.isInteger(value) || value < 1) throw new TypeError('concurrency must be a positive integer');
  concurrency = value;
};

const parsers = {
  bmp: parseBmp,
  gif: parseGif,
  jpg: parseJpeg,
  ktx: parseKtx,
  png: parsePng,
  psd: parsePsd,
  svg: parseSvg,
  tiff: parseTiff,
  webp: parseWebp,
};

void concurrency;

module.exports = imageSize;
