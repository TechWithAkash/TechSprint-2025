/**
 * PWA Icon Generator Script
 * 
 * This script generates all required PWA icons from a base SVG file
 * Run: node scripts/generate-pwa-icons.js
 */

const fs = require('fs');
const path = require('path');

console.log('📱 PWA Icon Generator');
console.log('====================\n');

const sizes = [72, 96, 128, 144, 152, 192, 384, 512];
const inputSvg = path.join(__dirname, '../public/icons/icon-base.svg');
const outputDir = path.join(__dirname, '../public/icons');

// Check if sharp is installed
let sharp;
try {
    sharp = require('sharp');
    console.log('✅ Sharp library found\n');
} catch (error) {
    console.log('❌ Sharp library not found');
    console.log('📦 Installing Sharp...\n');
    console.log('Please run: npm install sharp --save-dev\n');
    console.log('Alternative methods:');
    console.log('1. Use online tool: https://www.pwabuilder.com/imageGenerator');
    console.log('2. Use ImageMagick (see ICON_GENERATION_GUIDE.md)');
    process.exit(1);
}

// Create output directory if it doesn't exist
if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
    console.log('📁 Created icons directory\n');
}

// Check if input SVG exists
if (!fs.existsSync(inputSvg)) {
    console.error('❌ Base icon not found:', inputSvg);
    console.log('\nPlease create a 512x512 icon at:');
    console.log(inputSvg);
    process.exit(1);
}

console.log('🎨 Generating icons from:', path.basename(inputSvg));
console.log('📂 Output directory:', outputDir);
console.log('\nGenerating sizes:', sizes.join(', '));
console.log('');

// Generate icons
let completed = 0;
let failed = 0;

sizes.forEach(async (size) => {
    const outputFile = path.join(outputDir, `icon-${size}x${size}.png`);

    try {
        await sharp(inputSvg)
            .resize(size, size, {
                fit: 'contain',
                background: { r: 255, g: 255, b: 255, alpha: 0 }
            })
            .png()
            .toFile(outputFile);

        completed++;
        console.log(`✅ Generated ${size}x${size}.png`);

        if (completed + failed === sizes.length) {
            console.log('\n🎉 Icon generation complete!');
            console.log(`✅ ${completed} icons created successfully`);
            if (failed > 0) {
                console.log(`❌ ${failed} icons failed`);
            }
            console.log('\n📱 Next steps:');
            console.log('1. Check the icons in public/icons/');
            console.log('2. Run: npm run build');
            console.log('3. Test PWA on mobile device');
        }
    } catch (error) {
        failed++;
        console.error(`❌ Failed to generate ${size}x${size}:`, error.message);
    }
});
