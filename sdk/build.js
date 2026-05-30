const fs = require('fs');
const path = require('path');

async function build() {
  const src = fs.readFileSync(path.join(__dirname, 'src/index.js'), 'utf8');

  // Full unminified version
  fs.writeFileSync(path.join(__dirname, 'dist/silentshield.js'), src);

  // Minified using terser (safe — doesn't break URLs in strings like the naive // regex does)
  let minCode = src;
  try {
    const { minify } = require('terser');
    const result = await minify(src, { compress: true, mangle: false, format: { comments: false } });
    minCode = result.code;
  } catch(e) {
    // Fallback: strip only block comments (safe), leave line comments alone
    console.warn('terser unavailable, using fallback minification:', e.message);
    minCode = src
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\n\s*\n/g, '\n')
      .replace(/^\s+/gm, '')
      .trim();
  }
  fs.writeFileSync(path.join(__dirname, 'dist/silentshield.min.js'), minCode);

  // ESM copy
  fs.writeFileSync(path.join(__dirname, 'dist/silentshield.esm.js'), src);

  console.log('✅ SDK built successfully:');
  console.log(`   silentshield.js:     ${(src.length/1024).toFixed(1)}KB`);
  console.log(`   silentshield.min.js: ${(minCode.length/1024).toFixed(1)}KB`);
}

build().catch(err => { console.error('Build failed:', err); process.exit(1); });
