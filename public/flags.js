/**
 * Country flags, shared by the feed (DOM) and the map (canvas).
 *
 * Windows ships no flag glyphs, so a regional-indicator pair renders as two
 * squashed letters rather than a flag. iOS, Android and macOS render them
 * properly. Detect which we are on once: where the pair composes into a single
 * glyph it is narrower than two separate indicators.
 */
function detect() {
  try {
    const c = document.createElement('canvas').getContext('2d');
    c.font = '20px sans-serif';
    return c.measureText('\u{1F1E6}\u{1F1FA}').width < c.measureText('\u{1F1E6}').width * 1.8;
  } catch {
    return false;
  }
}

export const EMOJI_FLAGS = detect();
document.documentElement.dataset.flags = EMOJI_FLAGS ? 'emoji' : 'text';

export const isCC = (cc) => typeof cc === 'string' && /^[A-Za-z]{2}$/.test(cc);
export const ccUpper = (cc) => (isCC(cc) ? cc.toUpperCase() : '');

/** The flag glyph, or null when this platform cannot draw one. */
export function flagGlyph(cc) {
  if (!EMOJI_FLAGS || !isCC(cc)) return null;
  return String.fromCodePoint(...[...cc.toUpperCase()].map((ch) => 0x1f1e6 + ch.charCodeAt(0) - 65));
}

/** Short label for a country: a flag where possible, otherwise the code. */
export const flagLabel = (cc) => flagGlyph(cc) ?? ccUpper(cc);

const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/** Flag glyph where available, otherwise a country-code chip. Returns HTML. */
export function flagHtml(cc) {
  if (!isCC(cc)) return '';
  const glyph = flagGlyph(cc);
  return glyph
    ? `<span class="flag">${glyph}</span>`
    : `<span class="flag flag-text">${escapeHtml(ccUpper(cc))}</span>`;
}
