import assert from 'node:assert/strict';
import test from 'node:test';
import path from 'node:path';
import { createRequire } from 'node:module';

const repoRoot = path.resolve(import.meta.dirname, '..');
const requireFromRepo = createRequire(path.join(repoRoot, 'package.json'));
const imageSize = requireFromRepo('./mobile/vendor/image-size');

test('safe image-size supports every image format Metro accepts', () => {
  const fixtures = [
    ['png', pngFixture(640, 480)],
    ['gif', gifFixture(320, 240)],
    ['jpg', jpegFixture(800, 600)],
    ['bmp', bmpFixture(1024, 768)],
    ['psd', psdFixture(1200, 900)],
    ['webp', webpFixture(512, 256)],
    ['svg', Buffer.from('<svg viewBox="0 0 300 200"></svg>')],
    ['ktx', ktxFixture(256, 128)],
    ['tiff', tiffFixture(90, 45)],
  ];

  for (const [type, input] of fixtures) {
    const result = imageSize(input);
    assert.equal(result.type, type, `${type} parser type`);
    assert.ok(result.width > 0 && result.height > 0, `${type} dimensions`);
  }
  assert.deepEqual(imageSize.types, ['bmp', 'gif', 'jpg', 'ktx', 'png', 'psd', 'svg', 'tiff', 'webp']);
});

test('safe image-size rejects vulnerable parser formats before parsing', () => {
  const dangerousInputs = [
    Buffer.from('....ftypheic....', 'ascii'),
    Buffer.from([0x69, 0x63, 0x6e, 0x73, 0x00, 0x00, 0x00, 0x00]),
    Buffer.from([0xff, 0x0a, 0x00, 0x00, 0x00, 0x00]),
  ];
  for (const input of dangerousInputs) {
    assert.throws(() => imageSize(input), /unsupported file type|invalid image dimensions/);
  }
});

test('safe image-size validates bounds and honors parser disable controls', () => {
  assert.throws(() => imageSize(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])), /truncated PNG header/);
  imageSize.disableTypes(['png']);
  assert.throws(() => imageSize(pngFixture(4, 4)), /disabled file type: png/);
  imageSize.disableTypes([]);
  assert.deepEqual(imageSize(pngFixture(4, 4)), { width: 4, height: 4, type: 'png' });
});

test('safe image-size exposes no vulnerable parser modules or runtime dependencies', () => {
  const packageJson = requireFromRepo('./mobile/vendor/image-size/package.json');
  assert.ok(packageJson.version.startsWith('2.0.3-scriptureforge.'));
  assert.deepEqual(packageJson.dependencies, undefined);
  assert.deepEqual(imageSize.types.filter((type) => ['heif', 'icns', 'jxl', 'jxl-stream'].includes(type)), []);
});

function pngFixture(width, height) {
  const input = Buffer.alloc(24);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(input);
  input.writeUInt32BE(width, 16);
  input.writeUInt32BE(height, 20);
  return input;
}

function gifFixture(width, height) {
  const input = Buffer.alloc(10, 0);
  Buffer.from('GIF89a', 'ascii').copy(input);
  input.writeUInt16LE(width, 6);
  input.writeUInt16LE(height, 8);
  return input;
}

function jpegFixture(width, height) {
  const input = Buffer.alloc(21, 0);
  input.set([0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08], 0);
  input.writeUInt16BE(height, 7);
  input.writeUInt16BE(width, 9);
  return input;
}

function bmpFixture(width, height) {
  const input = Buffer.alloc(26, 0);
  input[0] = 0x42;
  input[1] = 0x4d;
  input.writeInt32LE(width, 18);
  input.writeInt32LE(height, 22);
  return input;
}

function psdFixture(width, height) {
  const input = Buffer.alloc(26, 0);
  Buffer.from('8BPS', 'ascii').copy(input);
  input.writeUInt32BE(height, 14);
  input.writeUInt32BE(width, 18);
  return input;
}

function webpFixture(width, height) {
  const input = Buffer.alloc(30, 0);
  Buffer.from('RIFF', 'ascii').copy(input, 0);
  Buffer.from('WEBP', 'ascii').copy(input, 8);
  Buffer.from('VP8X', 'ascii').copy(input, 12);
  writeUInt24LE(input, width - 1, 24);
  writeUInt24LE(input, height - 1, 27);
  return input;
}

function ktxFixture(width, height) {
  const input = Buffer.alloc(44, 0);
  Buffer.from([0xab, 0x4b, 0x54, 0x58, 0x20, 0x31, 0x31, 0xbb, 0x0d, 0x0a, 0x1a, 0x0a]).copy(input);
  input.writeUInt32LE(0x04030201, 12);
  input.writeUInt32LE(width, 36);
  input.writeUInt32LE(height, 40);
  return input;
}

function tiffFixture(width, height) {
  const input = Buffer.alloc(38, 0);
  input.set([0x49, 0x49, 0x2a, 0x00], 0);
  input.writeUInt32LE(8, 4);
  input.writeUInt16LE(2, 8);
  writeTiffEntry(input, 10, 256, width);
  writeTiffEntry(input, 22, 257, height);
  return input;
}

function writeTiffEntry(input, offset, tag, value) {
  input.writeUInt16LE(tag, offset);
  input.writeUInt16LE(4, offset + 2);
  input.writeUInt32LE(1, offset + 4);
  input.writeUInt32LE(value, offset + 8);
}

function writeUInt24LE(input, value, offset) {
  input[offset] = value & 0xff;
  input[offset + 1] = (value >>> 8) & 0xff;
  input[offset + 2] = (value >>> 16) & 0xff;
}
