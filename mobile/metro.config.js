const { getDefaultConfig } = require('expo/metro-config');
const imageSize = require('image-size');

// Keep Metro from invoking the image-size parsers covered by DRR-002.
const blockedImageTypes = ['heif', 'icns', 'jxl', 'jxl-stream'];
if (typeof imageSize.disableTypes === 'function') {
  imageSize.disableTypes(blockedImageTypes);
}

const config = getDefaultConfig(__dirname);
const blockedAssetExtensions = new Set(['avif', 'heic', 'heif', 'icns', 'jxl']);
config.resolver.assetExts = config.resolver.assetExts.filter(
  (assetExtension) => !blockedAssetExtensions.has(assetExtension.toLowerCase()),
);

module.exports = config;
