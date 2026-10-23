import { expect, test } from '@playwright/test';

async function boot(page: import('@playwright/test').Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('.cl-topbar')).toBeVisible();
}

async function prepareTwoSignerAggregate(page: import('@playwright/test').Page): Promise<void> {
  await page.locator('#c-count').fill('2');
  await page.locator('#c-keygen').click();
  await expect(page.locator('#c-sign')).toBeEnabled();
  await page.locator('#c-sign').click();
  await expect(page.locator('#c-aggregate')).toBeEnabled();
}

test('distinguishes this demo orientation from Ethereum consensus', async ({ page }) => {
  await boot(page);
  const comparison = page.locator('#section-e');
  await expect(comparison).toContainText('This demo (G₁ sig, G₂ key)');
  await expect(comparison).toContainText('96 bytes');
  await expect(comparison).toContainText('48 bytes');
  await expect(comparison).toContainText('Ethereum uses that opposite, minimal-public-key-size orientation');
  await expect(comparison).toContainText('48-byte G₁ keys and 96-byte G₂ signatures');
});

test('labels the exposed GT bytes as a raw diagnostic rather than a wire standard', async ({ page }) => {
  await boot(page);
  const details = page.locator('#section-a .gory-details');
  await details.locator('summary').click();
  await expect(details).toContainText('576-byte raw diagnostic value');
  await expect(details).toContainText('not a claim that protocols use a standardized 576-byte');
});

test('aggregation reports linear construction and a two-term final equation', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await boot(page);
  await prepareTwoSignerAggregate(page);
  await page.locator('#c-aggregate').click();

  await expect(page.locator('#c-output')).toContainText('O(n) point additions');
  await expect(page.locator('#c-output')).toContainText('Final equation: 2 pairing terms');
  await expect(page.locator('#c-grid')).toContainText('Building the two aggregate points takes O(n) point additions');
  await expect(page.locator('#c-output')).not.toContainText('O(1) total work');
});

test('editing the message retires an in-flight aggregate result', async ({ page }) => {
  await boot(page);
  await prepareTwoSignerAggregate(page);

  await page.locator('#c-aggregate').click();
  await expect(page.locator('#c-grid')).toHaveAttribute('aria-busy', 'true');
  await page.locator('#c-msg').fill('newer learner message');

  await expect(page.locator('#c-output')).toContainText('Message changed — sign again.');
  await expect(page.locator('#c-aggregate')).toBeDisabled();
  await page.waitForTimeout(900);
  await expect(page.locator('#c-grid')).not.toContainText('Aggregated (2 signers)');
  await expect(page.locator('#c-output')).toContainText('Message changed — sign again.');
});

test('changing the count retires in-flight key generation', async ({ page }) => {
  await boot(page);
  await page.locator('#c-count').fill('100');
  await page.locator('#c-keygen').click();
  await expect(page.locator('#c-grid')).toHaveAttribute('aria-busy', 'true');
  await page.locator('#c-count').fill('2');

  await expect(page.locator('#c-output')).toContainText('Signer count changed — generate keypairs again.');
  await expect(page.locator('#c-sign')).toBeDisabled();
  await expect(page.locator('#c-grid')).toBeEmpty();
  await page.waitForTimeout(500);
  await expect(page.locator('#c-sign')).toBeDisabled();
});

test('the encoded message bound cannot be bypassed through the DOM', async ({ page }) => {
  await boot(page);
  await page.locator('#b-keygen').click();
  await expect(page.locator('#b-sign')).toBeEnabled();
  await page.locator('#b-msg').evaluate((input) => input.removeAttribute('maxlength'));
  await page.locator('#b-msg').fill('é'.repeat(4096));
  await page.locator('#b-sign').click();

  await expect(page.locator('#b-verdict')).toContainText('Message must be at most 4096 UTF-8 bytes.');
  await expect(page.locator('#b-verify')).toBeDisabled();
});

test('rogue-key defense uses the distinct proof domain and rejects the rogue key', async ({ page }) => {
  await boot(page);
  await page.locator('#d-attack').click();
  await expect(page.locator('#d-output')).toContainText('FORGERY ACCEPTED');
  await page.locator('#d-defend').click();

  await expect(page.locator('#d-output')).toContainText('PoP INVALID — key rejected');
  await expect(page.locator('#d-output')).toContainText('dedicated BLS_POP_… domain');
  await expect(page.locator('#d-output')).toContainText('Ethereum’s deposit signature serves a related registration purpose');
});
