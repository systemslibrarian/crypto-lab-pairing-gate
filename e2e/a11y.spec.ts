import { test } from '@playwright/test';
import { boot, driveAllStates, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * All four live sections are driven the way a visitor reaches them: the
 * bilinearity playground recomputed and its full G_T pair revealed, the
 * field-tower explainer opened, a keypair generated and a message signed,
 * verified, revealed byte for byte, tampered and re-verified into its failing
 * verdict, four signatures aggregated down to two pairings, the rogue-key
 * forgery mounted and then rejected by proof-of-possession — and each of the
 * three sections reset back to its empty shell. Every resulting state is
 * scanned in both themes at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no panel is
 * force-revealed, why each scan asserts its content first, and why
 * `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
  });
}
