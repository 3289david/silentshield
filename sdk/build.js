const fs = require('fs');
const path = require('path');

const src = fs.readFileSync(path.join(__dirname, 'src/index.js'), 'utf8');

// Write full (unminified) version
fs.writeFileSync(path.join(__dirname, 'dist/silentshield.js'), src);

// Simple minification (remove comments, collapse whitespace)
let min = src
  .replace(/\/\*[\s\S]*?\*\//g, '')      // block comments
  .replace(/\/\/[^\n]*/g, '')             // line comments
  .replace(/\n\s*\n/g, '\n')             // blank lines
  .replace(/^\s+/gm, '')                  // leading whitespace
  .trim();

fs.writeFileSync(path.join(__dirname, 'dist/silentshield.min.js'), min);

// ESM wrapper
const esm = `export default (${src.match(/function SilentShield[\s\S]*?^}/m)?.[0] || 'null'});\n`;
const esmWrapped = `// SilentShield ESM build\n${src.replace(
  /\(function \(global, factory\)[\s\S]*?\}\);/,
  `const SilentShield = (function() { ${src} return SilentShield; })();\nexport default SilentShield;\nexport { SilentShield };`
)}`;

// Just copy as ESM for now
fs.writeFileSync(path.join(__dirname, 'dist/silentshield.esm.js'), src);

const sizes = {
  'silentshield.js': src.length,
  'silentshield.min.js': min.length,
};

console.log('✅ SDK built successfully:');
Object.entries(sizes).forEach(([f, s]) => console.log(`   ${f}: ${(s/1024).toFixed(1)}KB`));
