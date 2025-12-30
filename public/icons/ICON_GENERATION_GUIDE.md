# PWA Icon Generation Script

This script helps you create PWA icons in all required sizes.

## Option 1: Using Online Tool (Easiest)

1. Create a 512x512 PNG icon with your app logo
2. Visit: https://www.pwabuilder.com/imageGenerator
3. Upload your 512x512 icon
4. Download the generated icons
5. Extract and place them in `public/icons/` folder

## Option 2: Using Sharp (Node.js)

Install Sharp:

```bash
npm install sharp --save-dev
```

Create a file `scripts/generate-icons.js`:

```javascript
const sharp = require("sharp");
const fs = require("fs");
const path = require("path");

const sizes = [72, 96, 128, 144, 152, 192, 384, 512];
const inputFile = "public/icon-base.png"; // Your 512x512 base icon
const outputDir = "public/icons";

// Create output directory if it doesn't exist
if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir, { recursive: true });
}

// Generate icons
sizes.forEach((size) => {
  sharp(inputFile)
    .resize(size, size)
    .toFile(path.join(outputDir, `icon-${size}x${size}.png`))
    .then(() => console.log(`✅ Generated ${size}x${size} icon`))
    .catch((err) => console.error(`❌ Error generating ${size}x${size}:`, err));
});

console.log("🎨 Generating PWA icons...");
```

Run:

```bash
node scripts/generate-icons.js
```

## Option 3: Using ImageMagick (CLI)

Install ImageMagick, then run:

```bash
# Create icons directory
mkdir -p public/icons

# Generate all sizes
magick convert icon-base.png -resize 72x72 public/icons/icon-72x72.png
magick convert icon-base.png -resize 96x96 public/icons/icon-96x96.png
magick convert icon-base.png -resize 128x128 public/icons/icon-128x128.png
magick convert icon-base.png -resize 144x144 public/icons/icon-144x144.png
magick convert icon-base.png -resize 152x152 public/icons/icon-152x152.png
magick convert icon-base.png -resize 192x192 public/icons/icon-192x192.png
magick convert icon-base.png -resize 384x384 public/icons/icon-384x384.png
magick convert icon-base.png -resize 512x512 public/icons/icon-512x512.png
```

## Temporary Placeholder Icons

For now, you can create simple placeholder icons using this SVG:

Create `public/icons/icon.svg`:

```svg
<svg width="512" height="512" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#10b981;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#14b8a6;stop-opacity:1" />
    </linearGradient>
  </defs>
  <rect width="512" height="512" rx="100" fill="url(#grad)"/>
  <text x="256" y="330" font-family="Arial, sans-serif" font-size="200" font-weight="bold" fill="white" text-anchor="middle">W</text>
</svg>
```

## Required Sizes

- 72x72 - Android devices
- 96x96 - Android devices
- 128x128 - Android devices
- 144x144 - Android devices
- 152x152 - iOS devices
- 192x192 - Android devices (standard)
- 384x384 - Android devices
- 512x512 - Android devices (splash screens)

## After Generating Icons

1. Place all icons in `public/icons/` folder
2. Icons should be named: `icon-[size]x[size].png`
3. Rebuild your app: `npm run build`
4. Test on mobile devices

## Testing PWA Icons

1. Open Chrome DevTools
2. Go to Application tab
3. Click "Manifest" in sidebar
4. Check if all icons are loaded correctly

## Screenshots for App Stores

Create screenshots:

- Mobile: 540x720 (narrow form factor)
- Desktop: 1280x720 (wide form factor)

Place in `public/screenshots/`:

- dashboard.png
- desktop.png
