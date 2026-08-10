import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures, type NonTextFailure } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over an empty container passes having checked
 *     nothing, and at first paint three of this lab's four live sections are
 *     empty: no keypair, no signature, no pairing values, no verdict, no
 *     signer grid, no aggregation diagram, no forgery. Every control past the
 *     first in each section ships `disabled`. The colours that carry the
 *     lab's claims — the VALID and INVALID badges, the `.error-text` lead, the
 *     `.diff-mark` nibble that proves two G_T values differ, the G1/G2/G_T
 *     group inks — exist only in those later states, and the headline claim
 *     (a rogue-key forgery the aggregate key ACCEPTS) is its own section's
 *     first click.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // The whole page is rendered from `main.ts`, so a navigation that resolves
  // proves nothing. Require one control from each of the four live sections.
  await expect(page.locator('#pg-toggle')).toBeVisible();
  await expect(page.locator('#b-keygen')).toBeVisible();
  await expect(page.locator('#c-keygen')).toBeVisible();
  await expect(page.locator('#d-attack')).toBeVisible();
  // Sections B, C and D are genuinely empty here — every downstream control is
  // disabled and no verdict, badge or G_T value exists — so a scan at this
  // point proves nothing about them. That is the whole reason
  // `driveAllStates` exists.
  await expect(page.locator('#b-sign')).toBeDisabled();
  await expect(page.locator('#b-verdict')).toBeEmpty();
  await expect(page.locator('#c-sign')).toBeDisabled();
  await expect(page.locator('#d-output')).toBeEmpty();

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints 48- and 96-byte compressed curve points as
 * hex, reveals all 576 bytes of a G_T element on BOTH sides of the pairing
 * equation at once, and lays a grid of signer cards beside an aggregation
 * diagram.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide table inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That
    // cost a run elsewhere in this fleet (a 980px table was reported while the
    // real overflow was 15px of something else), and this lab has decoys of
    // its own: the G_T value blocks and the signer grid are both `overflow-x:
    // auto`, so their contents are wide and clipped rather than pushing.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  expect(violations, `axe violations in state: ${label}`).toEqual([]);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  expect(unexplainedIncomplete, `axe incomplete results in state: ${label}`).toEqual([]);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  expect(contrast, `measured contrast failures in state: ${label}`).toEqual([]);

  await expectNoNewNonTextFailures(page, label);
  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Four things shape this drive:
 *
 *  - THE FAILING VERDICTS ARE THE POINT, AND THEY PAINT INK NOTHING ELSE DOES.
 *    Section B's tampered verify renders `.badge.invalid` and `.error-text`;
 *    Section D's rogue-key attack renders "FORGERY ACCEPTED" — a red badge that
 *    only exists when the attack succeeds, which is the entire claim of the
 *    section. Both are scanned in their own right, and so is the passing
 *    verdict that precedes each, because a gate that scans only the end state
 *    sees one of the two.
 *
 *  - THE RESET STATES ARE REAL STATES. All three sections ship a Reset that
 *    returns them to an empty, re-disabled shell. The gate this replaces never
 *    pressed one, so nothing verified that reset leaves a coherent page rather
 *    than a half-torn-down one.
 *
 *  - THE MERGE ANIMATION IS DELIBERATELY NOT EXERCISED. Section C flies each
 *    signer card into one of two piles, and `aggregate` guards that whole block
 *    behind `!reduceMotion()`. With the preference set — which `boot` asserts
 *    is actually in effect — the cards are never given `.flying` and never
 *    reach `opacity: 0`. Scanning mid-flight would mean scanning a state this
 *    reader can never see. It is recorded here so the next reader does not add
 *    a wait for an animation that is correctly skipped.
 *
 *  - THE PAIRINGS ARE SLOW. Every step is awaited on its own completion signal —
 *    the next button enabling, a verdict rendering, the aggregate row
 *    appearing — never on a fixed timeout.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  await scan(page, `${theme} / first paint`);

  await page.locator('a.cl-skip-link').focus();
  await scan(page, `${theme} / skip link focused`);

  // ── Section A: the bilinearity playground ────────────────────────────────
  // It computes on load, so its badge exists at first paint; what does not is
  // the full 576-byte G_T pair behind the reveal toggle.
  await expect(page.locator('#pg-output .badge')).toBeVisible();
  await page.locator('#pg-a').fill('7');
  await page.locator('#pg-a').dispatchEvent('input');
  await expect(page.locator('#pg-a-display')).toHaveText('7');
  await scan(page, `${theme} / bilinearity recomputed for a = 7`);

  await page.locator('#pg-toggle').click();
  await expect(page.locator('#pg-output .pg-value.full').first()).toBeVisible();
  await scan(page, `${theme} / full G_T values revealed`);

  // The one <details> on the page — the field-tower explainer.
  await page.locator('details.gory-details > summary').click();
  await expect(page.locator('details.gory-details')).toHaveAttribute('open', '');
  await scan(page, `${theme} / field-tower details expanded`);

  // ── Section B: sign, verify, tamper, verify again ────────────────────────
  await page.locator('#b-keygen').click();
  await expect(page.locator('#b-sign')).toBeEnabled({ timeout: 120_000 });
  await scan(page, `${theme} / keypair generated`);

  await page.locator('#b-sign').click();
  await expect(page.locator('#b-verify')).toBeEnabled({ timeout: 120_000 });
  await expect(page.locator('#b-sig-val')).not.toBeEmpty();
  await scan(page, `${theme} / message signed`);

  await page.locator('#b-verify').click();
  await expect(page.locator('#b-verdict .badge.valid').first()).toBeVisible({ timeout: 120_000 });
  await scan(page, `${theme} / signature verifies`);

  // The full 576-byte pair on both sides of the pairing equation.
  await page.locator('#b-reveal').click();
  await expect(page.locator('#b-left-val.gt-full')).toBeVisible();
  await scan(page, `${theme} / both G_T sides revealed in full`);

  // Tamper, then re-verify: the INVALID badge and `.error-text` lead exist
  // only here, and are a different palette from everything above.
  await page.locator('#b-tamper').click();
  await page.locator('#b-verify').click();
  await expect(page.locator('#b-verdict .badge.invalid').first()).toBeVisible({ timeout: 120_000 });
  await scan(page, `${theme} / tampered message fails verification`);

  await page.locator('#b-reset').click();
  await expect(page.locator('#b-sign')).toBeDisabled();
  await expect(page.locator('#b-verdict')).toBeEmpty();
  await scan(page, `${theme} / section B reset`);

  // ── Section C: aggregation ───────────────────────────────────────────────
  await page.locator('#c-count').fill('4');
  await page.locator('#c-count').dispatchEvent('input');
  await expect(page.locator('#c-count-display')).toHaveText('4');
  await page.locator('#c-keygen').click();
  await expect(page.locator('#c-sign')).toBeEnabled({ timeout: 120_000 });
  await expect(page.locator('#c-grid .signer-card')).toHaveCount(4);
  await scan(page, `${theme} / four signer keypairs`);

  await page.locator('#c-sign').click();
  await expect(page.locator('#c-aggregate')).toBeEnabled({ timeout: 120_000 });
  await scan(page, `${theme} / four signatures produced`);

  await page.locator('#c-aggregate').click();
  await expect(page.locator('#c-grid .aggregate')).toBeVisible({ timeout: 120_000 });
  await expect(page.locator('.agg-diagram')).toBeVisible();
  await scan(page, `${theme} / four signatures aggregated into two pairings`);

  await page.locator('#c-reset').click();
  await expect(page.locator('#c-sign')).toBeDisabled();
  await scan(page, `${theme} / section C reset`);

  // ── Section D: the rogue-key attack and the proof-of-possession defence ──
  await page.locator('#d-attack').click();
  await expect(page.locator('#d-defend')).toBeEnabled({ timeout: 120_000 });
  await expect(page.locator('#d-output .badge.invalid').first()).toBeVisible();
  await scan(page, `${theme} / rogue-key forgery accepted`);

  await page.locator('#d-defend').click();
  await expect(page.locator('#d-output .badge')).toHaveCount(2, { timeout: 120_000 });
  await scan(page, `${theme} / proof-of-possession rejects the forgery`);

  await page.locator('#d-reset').click();
  await expect(page.locator('#d-defend')).toBeDisabled();
  await scan(page, `${theme} / section D reset`);
}
