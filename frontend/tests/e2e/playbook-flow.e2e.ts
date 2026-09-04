import { expect, test } from '@playwright/test'

const timestamp = '2026-09-05T00:00:00Z'
const playbookId = '00000000-0000-4000-8000-000000000070'
const content = '---\n- name: Managed site\n  hosts: all\n  gather_facts: false\n  tasks: []\n'

test('database and mounted Playbooks render and a database Playbook can be validated and saved', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('app.locale', 'en-US'))
  let createPayload: Record<string, unknown> | null = null
  const databaseSummary = {
    source: 'DATABASE',
    playbookId,
    path: null,
    name: 'Managed site',
    description: 'Stored in PostgreSQL',
    enabled: true,
    editable: true,
    revision: 2,
    version: 3,
    size: content.length,
    modifiedAt: timestamp,
    sha256: 'c'.repeat(64),
  }
  const mountedSummary = {
    source: 'MOUNT',
    playbookId: null,
    path: 'playbooks/status.yml',
    name: 'Status',
    description: '',
    enabled: true,
    editable: false,
    revision: null,
    version: null,
    size: 64,
    modifiedAt: timestamp,
    sha256: 'd'.repeat(64),
  }

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    if (path === '/api/v1/auth/session') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          userId: '00000000-0000-4000-8000-000000000001',
          username: 'admin',
          expiresAt: '2099-09-05T00:00:00Z',
        }),
      })
      return
    }
    if (path === '/api/v1/playbooks/config') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          sourceMode: 'both',
          databaseEnabled: true,
          databaseWritable: true,
          mountEnabled: true,
          mountReadOnly: true,
        }),
      })
      return
    }
    if (path === '/api/v1/playbooks' && request.method() === 'GET') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify([databaseSummary, mountedSummary]),
      })
      return
    }
    if (path === '/api/v1/playbooks/validate') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ valid: true, output: 'syntax check passed' }),
      })
      return
    }
    if (path === '/api/v1/playbooks/database' && request.method() === 'POST') {
      createPayload = request.postDataJSON() as Record<string, unknown>
      await route.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify({
          ...databaseSummary,
          playbookId: '00000000-0000-4000-8000-000000000071',
          name: createPayload.name,
          revision: 1,
          version: 1,
          content: createPayload.content,
          validatorVersion: 'ansible-core test',
          validatedAt: timestamp,
        }),
      })
      return
    }
    await route.fulfill({ status: 404, contentType: 'application/json', body: '{}' })
  })

  await page.goto('/playbooks')
  await expect(page.getByRole('heading', { name: 'Playbooks' }).last()).toBeVisible()
  await expect(page.getByText('Managed site', { exact: true })).toBeVisible()
  await expect(page.getByText('Read-only mount', { exact: true })).toBeVisible()

  await page.getByRole('button', { name: 'New Playbook' }).click()
  const dialog = page.getByRole('dialog', { name: 'New database Playbook' })
  await dialog.getByLabel('Name').fill('Created in browser')
  await dialog.getByLabel('Playbook YAML').fill(content)
  await dialog.getByRole('button', { name: 'Syntax check' }).click()
  await expect(dialog.getByText('syntax check passed')).toBeVisible()
  await dialog.getByRole('button', { name: 'Save' }).click()

  await expect.poll(() => createPayload).not.toBeNull()
  expect(createPayload).toMatchObject({
    name: 'Created in browser',
    content,
    enabled: true,
  })
})
