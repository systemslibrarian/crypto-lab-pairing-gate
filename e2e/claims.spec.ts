import { expect, test } from '@playwright/test';

/**
 * Section B's tamper exhibit promises "the first differing nibble highlighted"
 * between the two G_T values. It never appeared: the bit-flip candidates
 * usually fail to decode, so the demo falls through to negating the signature,
 * whose pairing is the Fp12 conjugate — the two 576-byte values agree for
 * their first 288 bytes. The highlighter only scanned the first 32, found
 * nothing, and rendered two identical-looking strings under a verdict
 * announcing they were different.
 *
 * These drive the real exhibit and assert the evidence is actually visible.
 */

async function signThenTamper(page: import('@playwright/test').Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('#cl-theme-toggle')).toBeVisible();

  await page.locator('#b-keygen').click();
  await expect(page.locator('#b-sign')).toBeEnabled();
  await page.locator('#b-sign').click();
  await expect(page.locator('#b-sig-val')).toBeVisible();
  await page.locator('#b-tamper').click();
}

test('tampering shows the altered signature, not the original', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#cl-theme-toggle')).toBeVisible();
  await page.locator('#b-keygen').click();
  await expect(page.locator('#b-sign')).toBeEnabled();
  await page.locator('#b-sign').click();

  const sigVal = page.locator('#b-sig-val');
  await expect(sigVal).toBeVisible();
  const before = ((await sigVal.textContent()) ?? '').replace(/\s/g, '');
  expect(before.length, 'no signature rendered').toBeGreaterThan(0);

  await page.locator('#b-tamper').click();

  const after = ((await sigVal.textContent()) ?? '').replace(/\s/g, '');
  expect(after, 'the displayed signature did not change after tampering').not.toBe(before);
  await expect(page.locator('#b-sig-label')).toContainText('ALTERED');
});

test('a failed verification actually highlights where the G_T values differ', async ({ page }) => {
  await signThenTamper(page);

  await page.locator('#b-verify').click();
  await expect(page.locator('#b-left-val')).toBeVisible();

  // The verdict must be the failing one...
  await expect(page.locator('.badge.invalid').first()).toBeVisible();
  await expect(page.locator('#b-verdict')).toContainText('different G_T element');

  // ...and the promised evidence must be on screen for BOTH sides.
  const leftMark = page.locator('#b-left-val mark.diff-mark');
  const rightMark = page.locator('#b-right-val mark.diff-mark');
  await expect(leftMark, 'no differing nibble highlighted on the left').toHaveCount(1);
  await expect(rightMark, 'no differing nibble highlighted on the right').toHaveCount(1);

  // The highlighted nibbles must genuinely differ from each other.
  const l = ((await leftMark.textContent()) ?? '').trim();
  const r = ((await rightMark.textContent()) ?? '').trim();
  expect(l).not.toBe('');
  expect(l, 'the "differing" nibbles are identical').not.toBe(r);

  // The two panels must not render as the same string, which is what the
  // learner used to see.
  const leftText = ((await page.locator('#b-left-val').textContent()) ?? '').replace(/\s/g, '');
  const rightText = ((await page.locator('#b-right-val').textContent()) ?? '').replace(/\s/g, '');
  expect(leftText, 'both G_T panels rendered identical text').not.toBe(rightText);
});

test('an untampered signature still verifies and claims no difference', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#cl-theme-toggle')).toBeVisible();
  await page.locator('#b-keygen').click();
  await expect(page.locator('#b-sign')).toBeEnabled();
  await page.locator('#b-sign').click();
  await page.locator('#b-verify').click();

  await expect(page.locator('.badge.valid').first()).toBeVisible();
  await expect(page.locator('#b-verdict')).toContainText('same');
  await expect(page.locator('#b-left-val mark.diff-mark')).toHaveCount(0);
});
