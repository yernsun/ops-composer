<script setup lang="ts">
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import Fluid from 'primevue/fluid'
import InputNumber from 'primevue/inputnumber'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import Select from 'primevue/select'
import Tag from 'primevue/tag'
import Textarea from 'primevue/textarea'
import ToggleSwitch from 'primevue/toggleswitch'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { computed, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'

import PageHeader from '@/components/PageHeader.vue'
import TargetPicker, { type TargetValue } from '@/components/TargetPicker.vue'
import {
  ApiRequestError,
  api,
  type DatabasePlaybookDto,
  type PlaybookDto,
  type PlaybookValidationDto,
} from '@/shared/api/client'

type PlaybookSource = PlaybookDto['source']
type PlaybookReferenceDto = NonNullable<PlaybookValidationDto['playbook']>

interface PlaybookForm {
  playbookId: string | null
  name: string
  description: string
  enabled: boolean
  content: string
  version: number
}

const DEFAULT_PLAYBOOK = `---
- name: Managed Playbook
  hosts: all
  gather_facts: false
  tasks:
    - name: Verify connectivity
      ansible.builtin.ping:
`
const MAX_PLAYBOOK_BYTES = 1024 * 1024

const { t, locale } = useI18n()
const router = useRouter()
const queryClient = useQueryClient()
const toast = useToast()
const confirm = useConfirm()
const sourceFilter = ref<'ALL' | PlaybookSource>('ALL')
const editorVisible = ref(false)
const executeVisible = ref(false)
const selected = ref<PlaybookDto | null>(null)
const validationOutput = ref('')
const target = ref<TargetValue>({ kind: 'ALL', hostIds: [], groupId: null })
const extraVarsText = ref('{}')
const tagsText = ref('')
const skipTagsText = ref('')
const timeoutSeconds = ref(1800)
const forks = ref(5)
const form = reactive<PlaybookForm>({
  playbookId: null,
  name: '',
  description: '',
  enabled: true,
  content: DEFAULT_PLAYBOOK,
  version: 1,
})

const playbooksQuery = useQuery({ queryKey: ['playbooks'], queryFn: api.playbooks })
const configQuery = useQuery({ queryKey: ['playbook-config'], queryFn: api.playbookConfig })
const playbooks = computed(() => {
  const values = playbooksQuery.data.value ?? []
  const filtered = sourceFilter.value === 'ALL'
    ? values
    : values.filter((playbook) => playbook.source === sourceFilter.value)
  return filtered.map((playbook) => ({
    ...playbook,
    referenceKey: `${playbook.source}:${playbook.playbookId ?? playbook.path}`,
  }))
})
const sourceOptions = computed(() => [
  { label: t('playbooks.allSources'), value: 'ALL' },
  { label: t('playbooks.databaseSource'), value: 'DATABASE' },
  { label: t('playbooks.mountSource'), value: 'MOUNT' },
])
const contentBytes = computed(() => new TextEncoder().encode(form.content).byteLength)
const canSave = computed(
  () =>
    form.name.trim().length > 0 &&
    form.content.length > 0 &&
    contentBytes.value <= MAX_PLAYBOOK_BYTES,
)

function reference(playbook: PlaybookDto): PlaybookReferenceDto {
  if (playbook.source === 'DATABASE') {
    if (!playbook.playbookId) throw new Error(t('playbooks.choose'))
    return { source: 'DATABASE', playbookId: playbook.playbookId }
  }
  if (!playbook.path) throw new Error(t('playbooks.choose'))
  return { source: 'MOUNT', path: playbook.path }
}

function showError(error: Error, summary = t('common.failed')): void {
  let detail = error.message
  if (error instanceof ApiRequestError) {
    if (error.code === 'playbook_version_conflict') detail = t('playbooks.versionConflict')
    if (error.code === 'playbook_source_disabled') detail = t('playbooks.sourceUnavailable')
    if (error.code === 'playbook_disabled') detail = t('playbooks.disabledRun')
  }
  toast.add({ severity: 'error', summary, detail, life: 7000 })
}

async function refreshPlaybooks(): Promise<void> {
  await queryClient.invalidateQueries({ queryKey: ['playbooks'] })
}

const validateMutation = useMutation({
  mutationFn: (input: PlaybookValidationDto) => api.validatePlaybook(input),
  onSuccess: (result) => {
    validationOutput.value = result.output
    toast.add({
      severity: result.valid ? 'success' : 'error',
      summary: result.valid ? t('playbooks.valid') : t('playbooks.invalid'),
      detail: result.output.slice(-500),
      life: 7000,
    })
  },
  onError: (error) => showError(error, t('playbooks.invalid')),
})

const saveMutation = useMutation({
  mutationFn: () => {
    const payload = {
      name: form.name,
      description: form.description,
      enabled: form.enabled,
      content: form.content,
    }
    return form.playbookId
      ? api.updateDatabasePlaybook(form.playbookId, { ...payload, version: form.version })
      : api.createDatabasePlaybook(payload)
  },
  onSuccess: async () => {
    editorVisible.value = false
    await refreshPlaybooks()
    toast.add({ severity: 'success', summary: t('common.saved'), life: 2500 })
  },
  onError: (error) => showError(error),
})

const toggleMutation = useMutation({
  mutationFn: async (playbook: PlaybookDto) => {
    if (!playbook.playbookId) throw new Error(t('playbooks.readOnlyMount'))
    const detail = await queryClient.fetchQuery({
      queryKey: ['playbook', playbook.playbookId],
      queryFn: () => api.databasePlaybook(playbook.playbookId as string),
    })
    return api.updateDatabasePlaybook(playbook.playbookId, {
      name: detail.name,
      description: detail.description,
      enabled: !detail.enabled,
      content: detail.content,
      version: detail.version as number,
    })
  },
  onSuccess: async (playbook) => {
    await refreshPlaybooks()
    toast.add({
      severity: 'success',
      summary: playbook.enabled ? t('playbooks.enabled') : t('playbooks.disabled'),
      life: 2500,
    })
  },
  onError: (error) => showError(error),
})

const executeMutation = useMutation({
  mutationFn: async () => {
    if (!selected.value) throw new Error(t('playbooks.choose'))
    if (!selected.value.enabled) throw new Error(t('playbooks.disabledRun'))
    let extraVars: Record<string, unknown>
    try {
      const parsed: unknown = JSON.parse(extraVarsText.value)
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('extra vars must be an object')
      }
      extraVars = parsed as Record<string, unknown>
    } catch {
      throw new Error(t('playbooks.extraVarsInvalid'))
    }
    const split = (value: string) =>
      value.split(',').map((item) => item.trim()).filter(Boolean)
    return api.createPlaybookRun({
      target: {
        kind: target.value.kind,
        hostIds: target.value.hostIds,
        groupId: target.value.groupId,
      },
      playbook: reference(selected.value),
      extraVars,
      tags: split(tagsText.value),
      skipTags: split(skipTagsText.value),
      timeoutSeconds: timeoutSeconds.value,
      forks: forks.value,
    })
  },
  onSuccess: (run) => void router.push({ name: 'run-detail', params: { id: run.runId } }),
  onError: (error) => {
    if (
      error instanceof ApiRequestError &&
      error.code === 'host_key_confirmation_required'
    ) {
      toast.add({
        severity: 'warn',
        summary: t('playbooks.runFailed'),
        detail: t('hosts.confirmationRequiredRun'),
        life: 8000,
      })
      return
    }
    showError(error, t('playbooks.runFailed'))
  },
})

function newPlaybook(): void {
  Object.assign(form, {
    playbookId: null,
    name: '',
    description: '',
    enabled: true,
    content: DEFAULT_PLAYBOOK,
    version: 1,
  })
  validationOutput.value = ''
  editorVisible.value = true
}

async function editPlaybook(playbook: PlaybookDto): Promise<void> {
  if (!playbook.playbookId) return
  try {
    const detail: DatabasePlaybookDto = await queryClient.fetchQuery({
      queryKey: ['playbook', playbook.playbookId],
      queryFn: () => api.databasePlaybook(playbook.playbookId as string),
    })
    Object.assign(form, {
      playbookId: detail.playbookId,
      name: detail.name,
      description: detail.description,
      enabled: detail.enabled,
      content: detail.content,
      version: detail.version,
    })
    validationOutput.value = ''
    editorVisible.value = true
  } catch (error) {
    showError(error instanceof Error ? error : new Error(t('common.failed')))
  }
}

function validateRow(playbook: PlaybookDto): void {
  validationOutput.value = ''
  validateMutation.mutate({ playbook: reference(playbook) })
}

function validateDraft(): void {
  validationOutput.value = ''
  validateMutation.mutate({ content: form.content })
}

function removePlaybook(playbook: PlaybookDto): void {
  if (!playbook.playbookId || !playbook.version) return
  confirm.require({
    header: t('playbooks.deleteTitle'),
    message: t('playbooks.deleteConfirm', { name: playbook.name }),
    icon: 'pi pi-exclamation-triangle',
    rejectProps: { label: t('common.cancel'), severity: 'secondary', outlined: true },
    acceptProps: { label: t('common.delete'), severity: 'danger' },
    accept: async () => {
      try {
        await api.deleteDatabasePlaybook(playbook.playbookId as string, playbook.version as number)
        await refreshPlaybooks()
        toast.add({ severity: 'success', summary: t('common.deleted'), life: 2500 })
      } catch (error) {
        showError(error instanceof Error ? error : new Error(t('common.failed')))
      }
    },
  })
}

function openRun(playbook: PlaybookDto): void {
  selected.value = playbook
  extraVarsText.value = '{}'
  tagsText.value = ''
  skipTagsText.value = ''
  executeVisible.value = true
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  return `${(bytes / 1024).toFixed(bytes < 10240 ? 1 : 0)} KiB`
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(locale.value, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value))
}
</script>

<template>
  <div class="page-stack">
    <PageHeader :title="t('playbooks.title')" :description="t('playbooks.description')">
      <Button
        v-if="configQuery.data.value?.databaseWritable"
        icon="pi pi-plus"
        :label="t('playbooks.create')"
        @click="newPlaybook"
      />
    </PageHeader>

    <Message v-if="configQuery.data.value" severity="info" :closable="false">
      <i class="pi pi-database" />
      {{ t('playbooks.sourceModeHint', { mode: t(`playbooks.mode.${configQuery.data.value.sourceMode}`) }) }}
    </Message>

    <section class="surface-card">
      <div class="table-toolbar">
        <Select
          v-model="sourceFilter"
          :options="sourceOptions"
          option-label="label"
          option-value="value"
          :aria-label="t('playbooks.sourceFilter')"
        />
        <Button
          icon="pi pi-refresh"
          severity="secondary"
          outlined
          :aria-label="t('common.refresh')"
          :loading="playbooksQuery.isFetching.value"
          @click="playbooksQuery.refetch()"
        />
      </div>
      <DataTable
        :value="playbooks"
        :loading="playbooksQuery.isPending.value"
        data-key="referenceKey"
        paginator
        :rows="10"
        :rows-per-page-options="[10, 25, 50]"
        striped-rows
        state-storage="local"
        state-key="ops-composer-playbooks"
        :table-props="{ 'aria-label': t('playbooks.title') }"
      >
        <Column field="source" :header="t('playbooks.source')" sortable>
          <template #body="{ data }">
            <Tag
              :icon="data.source === 'DATABASE' ? 'pi pi-database' : 'pi pi-folder'"
              :severity="data.source === 'DATABASE' ? 'info' : 'secondary'"
              :value="data.source === 'DATABASE' ? t('playbooks.databaseSource') : t('playbooks.readOnlyMount')"
            />
          </template>
        </Column>
        <Column field="name" :header="t('playbooks.name')" sortable>
          <template #body="{ data }">
            <div class="table-primary">
              <strong>{{ data.name }}</strong>
              <small v-if="data.description">{{ data.description }}</small>
              <code v-else-if="data.path">{{ data.path }}</code>
            </div>
          </template>
        </Column>
        <Column field="enabled" :header="t('common.status')" sortable>
          <template #body="{ data }">
            <Tag
              :severity="data.enabled ? 'success' : 'secondary'"
              :value="data.enabled ? t('status.ENABLED') : t('status.DISABLED')"
            />
          </template>
        </Column>
        <Column field="revision" :header="t('playbooks.revision')" sortable>
          <template #body="{ data }">
            <span v-if="data.revision">r{{ data.revision }}</span>
            <code v-else :title="data.sha256">{{ data.sha256?.slice(0, 12) ?? '—' }}</code>
          </template>
        </Column>
        <Column field="size" :header="t('playbooks.size')" sortable>
          <template #body="{ data }">{{ formatSize(data.size ?? 0) }}</template>
        </Column>
        <Column field="modifiedAt" :header="t('playbooks.updatedAt')" sortable>
          <template #body="{ data }">{{ data.modifiedAt ? formatDate(data.modifiedAt) : '—' }}</template>
        </Column>
        <Column :header="t('common.actions')" frozen align-frozen="right">
          <template #body="{ data }">
            <div class="row-actions">
              <Button icon="pi pi-check-circle" text rounded :aria-label="t('playbooks.validate')" :loading="validateMutation.isPending.value" @click="validateRow(data)" />
              <template v-if="data.source === 'DATABASE'">
                <Button icon="pi pi-pencil" text rounded :aria-label="t('common.edit')" @click="editPlaybook(data)" />
                <Button :icon="data.enabled ? 'pi pi-pause' : 'pi pi-check'" text rounded :aria-label="data.enabled ? t('playbooks.disable') : t('playbooks.enable')" :loading="toggleMutation.isPending.value" @click="toggleMutation.mutate(data)" />
                <Button icon="pi pi-trash" severity="danger" text rounded :aria-label="t('common.delete')" @click="removePlaybook(data)" />
              </template>
              <Button icon="pi pi-play" :label="t('playbooks.run')" text size="small" :disabled="!data.enabled" @click="openRun(data)" />
            </div>
          </template>
        </Column>
        <template #empty>
          <div class="empty-state compact-empty">
            <i class="pi pi-folder-open" />
            <h3>{{ t('playbooks.empty') }}</h3>
            <p>{{ t('playbooks.emptyHint') }}</p>
          </div>
        </template>
      </DataTable>
    </section>

    <Dialog v-model:visible="editorVisible" modal :header="form.playbookId ? t('playbooks.editTitle', { name: form.name }) : t('playbooks.createTitle')" :style="{ width: 'min(980px, 97vw)' }">
      <Fluid>
        <form id="playbook-editor-form" class="form-grid two-columns" @submit.prevent="saveMutation.mutate()">
          <div class="field"><label for="playbook-name">{{ t('playbooks.name') }}</label><InputText id="playbook-name" v-model="form.name" maxlength="128" required /></div>
          <label class="switch-field" for="playbook-enabled"><ToggleSwitch id="playbook-enabled" v-model="form.enabled" /><span>{{ t('playbooks.enabledField') }}</span></label>
          <div class="field span-2"><label for="playbook-description">{{ t('common.description') }}</label><InputText id="playbook-description" v-model="form.description" maxlength="1024" /></div>
          <div class="field span-2">
            <div class="field-heading">
              <label for="playbook-content">{{ t('playbooks.yamlContent') }}</label>
              <small :class="{ 'field-error': contentBytes > MAX_PLAYBOOK_BYTES }">{{ t('playbooks.byteCount', { count: contentBytes, limit: MAX_PLAYBOOK_BYTES }) }}</small>
            </div>
            <Textarea id="playbook-content" v-model="form.content" rows="22" class="code-input playbook-editor" spellcheck="false" required />
            <small class="field-hint">{{ t('playbooks.databaseIsolationHint') }}</small>
          </div>
          <Message v-if="validationOutput" class="span-2" severity="secondary" :closable="false"><pre class="validation-output">{{ validationOutput }}</pre></Message>
        </form>
      </Fluid>
      <template #footer>
        <Button :label="t('common.cancel')" severity="secondary" text @click="editorVisible = false" />
        <Button icon="pi pi-check-circle" :label="t('playbooks.validate')" severity="secondary" outlined :loading="validateMutation.isPending.value" :disabled="!form.content" @click="validateDraft" />
        <Button type="submit" form="playbook-editor-form" icon="pi pi-save" :label="t('common.save')" :loading="saveMutation.isPending.value" :disabled="!canSave" />
      </template>
    </Dialog>

    <Dialog v-model:visible="executeVisible" modal :header="t('playbooks.runTitle', { name: selected?.name ?? '' })" :style="{ width: 'min(900px, 96vw)' }">
      <Fluid>
        <form id="playbook-run-form" class="form-grid two-columns" @submit.prevent="executeMutation.mutate()">
          <Message class="span-2" severity="info" :closable="false">{{ selected?.source === 'DATABASE' ? t('playbooks.pinnedRevision', { revision: selected?.revision }) : t('playbooks.mountedHash', { hash: selected?.sha256.slice(0, 12) }) }}</Message>
          <div class="span-2"><TargetPicker v-model="target" /></div>
          <div class="field span-2"><label for="extra-vars">{{ t('playbooks.extraVars') }}</label><Textarea id="extra-vars" v-model="extraVarsText" rows="7" class="code-input" /></div>
          <div class="field"><label for="tags">{{ t('playbooks.tags') }}</label><InputText id="tags" v-model="tagsText" :placeholder="t('playbooks.tagsHint')" /></div>
          <div class="field"><label for="skip-tags">{{ t('playbooks.skipTags') }}</label><InputText id="skip-tags" v-model="skipTagsText" :placeholder="t('playbooks.tagsHint')" /></div>
          <div class="field"><label for="playbook-timeout">{{ t('commands.timeout') }}</label><InputNumber id="playbook-timeout" v-model="timeoutSeconds" :min="1" :max="86400" suffix=" s" /></div>
          <div class="field"><label for="playbook-forks">{{ t('commands.forks') }}</label><InputNumber id="playbook-forks" v-model="forks" :min="1" :max="20" /></div>
        </form>
      </Fluid>
      <template #footer>
        <Button :label="t('common.cancel')" severity="secondary" text @click="executeVisible = false" />
        <Button type="submit" form="playbook-run-form" icon="pi pi-play" :label="t('playbooks.run')" :loading="executeMutation.isPending.value" />
      </template>
    </Dialog>
  </div>
</template>
