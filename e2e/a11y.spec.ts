import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG regression gate for the Pairing Gate (BLS12-381) demo.
 *
 * Scans the full page in BOTH themes with every interactive demo DRIVEN so the
 * dynamically-injected result regions (keys, signatures, pairing values,
 * verdicts, the rogue-key forgery and its PoP defense) are in the DOM when axe
 * runs. There are no <details> here — the app is a single scrolling page — but
 * we still generically expand any collapsibles / hidden panels for robustness.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Neutralize animation/transition/opacity so mid-flight states can't hide text
// from the contrast checker (the aggregation demo animates card merges).
async function killMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation-duration:0s!important;animation-delay:0s!important;
      transition-duration:0s!important;transition-delay:0s!important;
      opacity:1!important;scroll-behavior:auto!important;
    }`,
  });
}

// Force-reveal any class-toggled / [hidden] / display:none collapsibles so their
// content is scannable, and open every <details> (none today, cheap insurance).
async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const d of document.querySelectorAll('details')) (d as HTMLDetailsElement).open = true;
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) el.removeAttribute('hidden');
    for (const el of document.querySelectorAll<HTMLElement>('[aria-hidden="true"]')) {
      // don't unhide genuinely decorative icons; only panels
      if (el.matches('.panel,.accordion,.tab-panel,[role="tabpanel"]')) el.removeAttribute('aria-hidden');
    }
  });
}

// Drive every live demo so injected output regions exist during the scan.
async function driveDemos(page: Page): Promise<void> {
  // Section B — sign / verify / tamper.
  await page.locator('#b-keygen').click();
  await expect(page.locator('#b-sign')).toBeEnabled();
  await page.locator('#b-sign').click();
  await expect(page.locator('#b-verify')).toBeEnabled();
  await page.locator('#b-verify').click();
  await expect(page.locator('#b-verdict .badge')).toHaveCount(2);
  await page.locator('#b-tamper').click();
  await page.locator('#b-verify').click();

  // Section C — aggregate a small set (keeps the run fast) and verify.
  await page.locator('#c-count').fill('4');
  await page.locator('#c-keygen').click();
  await expect(page.locator('#c-sign')).toBeEnabled();
  await page.locator('#c-sign').click();
  await expect(page.locator('#c-aggregate')).toBeEnabled();
  await page.locator('#c-aggregate').click();
  await expect(page.locator('#c-grid .aggregate')).toBeVisible({ timeout: 15_000 });

  // Section D — run the rogue-key attack, then apply the PoP defense.
  await page.locator('#d-attack').click();
  await expect(page.locator('#d-defend')).toBeEnabled();
  await page.locator('#d-defend').click();
  await expect(page.locator('#d-output .badge')).toHaveCount(2);
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  // App is rendered by main.ts; wait for the shared header toggle + first demo.
  await expect(page.locator('#cl-theme-toggle')).toBeVisible();
  await expect(page.locator('#b-keygen')).toBeVisible();
  await killMotion(page);
});

test('no WCAG A/AA violations in dark theme (all demos driven)', async ({ page }) => {
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await driveDemos(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme (all demos driven)', async ({ page }) => {
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveDemos(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});
