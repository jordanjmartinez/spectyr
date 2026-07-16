/**
 * Application-owned copy must not contain em dashes (Stage 1 acceptance).
 * Scans the app's own source files with comments stripped: code comments are
 * not rendered copy, and third-party bundles are out of scope by design.
 */
const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, '..');

const collect = (dir) => {
  let files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === '__tests__' || entry.name === 'node_modules') continue;
      files = files.concat(collect(full));
    } else if (/\.(jsx?|css)$/.test(entry.name)) {
      files.push(full);
    }
  }
  return files;
};

const stripComments = (text) =>
  text
    .replace(/\/\*[\s\S]*?\*\//g, '')   // block comments (incl. JSX {/* */})
    .replace(/^\s*\/\/.*$/gm, '');      // full-line comments

test('no em dashes in application source copy (comments stripped)', () => {
  const offenders = [];
  for (const file of collect(SRC)) {
    const text = stripComments(fs.readFileSync(file, 'utf-8'));
    text.split('\n').forEach((line, i) => {
      if (line.includes('—')) {
        offenders.push(`${path.relative(SRC, file)}:${i + 1}: ${line.trim().slice(0, 80)}`);
      }
    });
  }
  expect(offenders).toEqual([]);
});
