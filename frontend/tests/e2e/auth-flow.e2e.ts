import { expect, test } from '@playwright/test'

test('application shell loads', async ({ page }) => {
  await page.route('**/api/v1/auth/session', async (route) => {
    await route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({
        code: 'authentication_required',
        message: 'authentication required',
        details: null,
        requestId: 'e2e-session',
      }),
    })
  })

  await page.goto('/')
  await expect(page.locator('.login-page')).toBeVisible()
  await expect(page.getByRole('heading', { name: 'OpsComposer' }).first()).toBeVisible()
})
