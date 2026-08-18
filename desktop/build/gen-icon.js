// Rasterize icon.svg into a multi-resolution icon.ico (+ a 256px png) for the app.
const sharp = require('sharp');
const pngToIcoMod = require('png-to-ico');
const pngToIco = pngToIcoMod.default || pngToIcoMod;
const fs = require('fs');
const path = require('path');

(async () => {
  const dir = __dirname;
  const svg = fs.readFileSync(path.join(dir, 'icon.svg'));
  const sizes = [16, 24, 32, 48, 64, 128, 256];
  const pngs = await Promise.all(
    sizes.map((s) => sharp(svg, { density: 384 }).resize(s, s).png().toBuffer())
  );
  await sharp(svg, { density: 384 }).resize(256, 256).png().toFile(path.join(dir, 'icon.png'));
  const ico = await pngToIco(pngs);
  fs.writeFileSync(path.join(dir, 'icon.ico'), ico);
  console.log('wrote icon.ico (' + ico.length + ' bytes) and icon.png');
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
