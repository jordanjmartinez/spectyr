/**
 * Stage 6 playtest fix 12: the hero tagline animates in with its siblings.
 *
 * The standing owner ruling stays binding: the subheading must never run
 * the blurFadeUp FILTER animation (it froze mid-blur on mobile and left
 * the line illegible). Its entrance is the blur-less animate-fade-up
 * variant (opacity + position only), slotted at 350ms between the h1
 * (300ms) and the Start control (400ms). Source-level pins, same style as
 * brand-lockup.
 */
import fs from 'fs';
import path from 'path';

const SRC = path.join(__dirname, '..');
const landing = fs.readFileSync(path.join(SRC, 'pages', 'Landing.jsx'), 'utf8');
const css = fs.readFileSync(path.join(SRC, 'index.css'), 'utf8');

// the tagline block: from its <p to the closing of its text
const tagline = landing.slice(
  landing.indexOf('Investigate alerts') - 400,
  landing.indexOf('Investigate alerts'));

test('the tagline enters via the blur-less variant at the 350ms slot', () => {
  expect(tagline).toContain('animate-fade-up');
  expect(tagline).toContain("animationDelay: '350ms'");
});

test('the owner ruling holds: the tagline never runs the filter animation', () => {
  expect(tagline).not.toContain('animate-blur-fade-up');
  const fadeUp = css.match(/@keyframes fadeUp\s*{[\s\S]*?\n}/)[0];
  expect(fadeUp).not.toContain('filter');
  // the class exists and animates fadeUp, not blurFadeUp
  const cls = css.match(/\.animate-fade-up\s*{[\s\S]*?}/)[0];
  expect(cls).toContain('fadeUp 1s ease-out forwards');
});

test('the hero sequence delays stay ordered: h1 300ms, tagline 350ms, Start 400ms', () => {
  const h1Idx = landing.indexOf("animationDelay: '300ms'");
  const tagIdx = landing.indexOf("animationDelay: '350ms'", landing.indexOf('Investigate alerts') - 400);
  const ctaIdx = landing.indexOf("animationDelay: '400ms'");
  expect(h1Idx).toBeGreaterThan(-1);
  expect(tagIdx).toBeGreaterThan(h1Idx);
  expect(ctaIdx).toBeGreaterThan(tagIdx);
});
