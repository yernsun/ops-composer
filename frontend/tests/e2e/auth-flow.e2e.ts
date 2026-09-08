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

test('password-only login stays in the SPA when TOTP policy is disabled', async ({ page }) => {
  const session = {
    userId: '00000000-0000-4000-8000-000000000001',
    username: 'admin',
    expiresAt: '2099-09-05T00:00:00Z',
    role: 'OWNER',
    permissions: [
      'asset:read',
      'asset:write',
      'credential:write',
      'playbook:write',
      'run:standard',
      'run:shell',
      'run:cancel',
      'web-shell:open',
      'audit:read',
      'user:read',
      'user:manage',
      'key:rotate',
    ],
    totpPolicyEnabled: false,
    mfaEnabled: false,
    mfaEnrollmentRequired: true,
    mfaVerifiedAt: null,
    elevatedUntil: '2099-09-05T00:10:00Z',
  }
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/v1/auth/session') {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({
          code: 'authentication_required',
          message: 'authentication required',
          details: null,
          requestId: 'e2e-password-session',
        }),
      })
      return
    }
    if (path === '/api/v1/auth/login') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(session) })
      return
    }
    if (path === '/api/v1/overview') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          hostCount: 0,
          enabledHostCount: 0,
          runsToday: 0,
          failedRuns: 0,
          activeRuns: 0,
        }),
      })
      return
    }
    await route.fulfill({ status: 404, contentType: 'application/json', body: '{}' })
  })

  await page.goto('/')
  await page.locator('#username').fill('admin')
  await page.locator('#password input').fill('password-only-test-value')
  await page.locator('form').first().evaluate((form: HTMLFormElement) => form.requestSubmit())

  await expect(page.locator('.console-shell')).toBeVisible()
  await expect(page).toHaveURL(/\/$/)
  await expect(page.locator('body')).not.toContainText('"nextStep"')
  await expect(page.locator('body')).not.toContainText('enrollmentSecret')
})
