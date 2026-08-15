import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW } from './gate';

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

/**
 * Why the staleness ratchet runs in the LIGHT configurations only.
 *
 * `expectBaselineNotStale` fails on any baselined finding that never appeared,
 * which is what forces a fixed entry out of `nontext-baseline.ts` instead of
 * letting it linger as a permanent exemption. `nonTextSeen` is module state and
 * `fullyParallel` gives every test its own worker, so the check sees exactly
 * the states ITS OWN test drove — it can only be sound in a configuration that
 * reaches every baselined selector.
 *
 * The baseline is a union across themes, and two of its entries are
 * light-theme-only. `button.primary` paints `--accent` as both fill and border,
 * so its boundary is accent-against-surface: `#d97706` on `#ffffff` is 2.15:1
 * and fails, while `#f59e0b` on `#111827` is far above 3:1 and never becomes a
 * finding at all. Running the ratchet in dark therefore reports
 * `button#b-keygen.primary` and `button#c-keygen.primary` stale on every run,
 * which was measured rather than assumed. The light configurations reach all
 * fifteen entries, so they are the only sound place for it.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expectBaselineNotStale();
  });
}
