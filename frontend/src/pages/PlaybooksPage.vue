<script setup lang="ts">
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import FileUpload from 'primevue/fileupload'
import Fluid from 'primevue/fluid'
import InputNumber from 'primevue/inputnumber'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import Password from 'primevue/password'
import Select from 'primevue/select'
import Splitter from 'primevue/splitter'
import SplitterPanel from 'primevue/splitterpanel'
import Tab from 'primevue/tab'
import TabList from 'primevue/tablist'
import TabPanel from 'primevue/tabpanel'
import TabPanels from 'primevue/tabpanels'
import Tabs from 'primevue/tabs'
import Tag from 'primevue/tag'
import Textarea from 'primevue/textarea'
import ToggleSwitch from 'primevue/toggleswitch'
import Tree from 'primevue/tree'
import type { TreeNode } from 'primevue/treenode'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { computed, reactive, ref } from 'vue'
import { onBeforeRouteLeave, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'

import PageHeader from '@/components/PageHeader.vue'
import TargetPicker, { type TargetValue } from '@/components/TargetPicker.vue'
import { useAuthorization } from '@/features/auth/authorization'
import {
  ApiRequestError,
  api,
  type DatabasePlaybookDto,
  type PlaybookDiffDto,
  type PlaybookDto,
  type PlaybookRevisionDto,
  type PlaybookRunDto,
  type PlaybookRunPreviewDto,
  type PlaybookValidationDto,
} from '@/shared/api/client'

type PlaybookSource = PlaybookDto['source']
type PlaybookReferenceDto = NonNullable<PlaybookValidationDto['playbook']>
interface WorkFile { path: string; content: string }
interface ParameterDefinition {
  name: string
  type: 'string' | 'integer' | 'number' | 'boolean'
  description: string
  required: boolean
  sensitive: boolean
  enumValues: unknown[] | null
  minimum?: number | undefined
  maximum?: number | undefined
  minLength?: number | undefined
  maxLength?: number | undefined
}

const DEFAULT_PLAYBOOK = `---
- name: Managed Playbook
  hosts: all
  gather_facts: false
  tasks:
    - name: Verify connectivity
      ansible.builtin.ping:
`
const DEFAULT_SCHEMA = JSON.stringify({ type: 'object', properties: {}, additionalProperties: false }, null, 2)

const { t, locale } = useI18n()
const router = useRouter()
const queryClient = useQueryClient()
const toast = useToast()
const confirm = useConfirm()
const { can } = useAuthorization()
const sourceFilter = ref<'ALL' | PlaybookSource>('ALL')
const editorVisible = ref(false)
const executeVisible = ref(false)
const diffVisible = ref(false)
const selected = ref<PlaybookDto | null>(null)
const selectedDetail = ref<DatabasePlaybookDto | null>(null)
const validationOutput = ref('')
const revisions = ref<PlaybookRevisionDto[]>([])
const revisionsLoading = ref(false)
const diff = ref<PlaybookDiffDto | null>(null)
const activePath = ref('playbook.yml')
const selectionKeys = ref<Record<string, boolean>>({ 'playbook.yml': true })
const newFilePath = ref('')
const baseline = ref('')
const target = ref<TargetValue>({ kind: 'ALL', hostIds: [], groupId: null })
const mountParametersText = ref('{}')
const runParameters = reactive<Record<string, unknown>>({})
const tagsText = ref('')
const skipTagsText = ref('')
const timeoutSeconds = ref(1800)
const forks = ref(5)
const checkMode = ref(false)
const preview = ref<PlaybookRunPreviewDto | null>(null)
const form = reactive({
  playbookId: null as string | null,
  name: '',
  description: '',
  enabled: true,
  files: [{ path: 'playbook.yml', content: DEFAULT_PLAYBOOK }] as WorkFile[],
  entrypoint: 'playbook.yml',
  parameterSchemaText: DEFAULT_SCHEMA,
  supportsCheckMode: false,
  version: 1,
})

const playbooksQuery = useQuery({ queryKey: ['playbooks'], queryFn: api.playbooks })
const configQuery = useQuery({ queryKey: ['playbook-config'], queryFn: api.playbookConfig })
const canWrite = computed(() => can('playbook:write'))
const canRun = computed(() => can('run:standard'))
const playbooks = computed(() => {
  const values = playbooksQuery.data.value ?? []
  const filtered = sourceFilter.value === 'ALL' ? values : values.filter((item) => item.source === sourceFilter.value)
  return filtered.map((item) => ({ ...item, referenceKey: `${item.source}:${item.playbookId ?? item.path}` }))
})
const sourceOptions = computed(() => [
  { label: t('playbooks.allSources'), value: 'ALL' },
  { label: t('playbooks.databaseSource'), value: 'DATABASE' },
  { label: t('playbooks.mountSource'), value: 'MOUNT' },
])
const activeFile = computed(() => form.files.find((item) => item.path === activePath.value) ?? null)
const totalBytes = computed(() => form.files.reduce((total, item) => total + new TextEncoder().encode(item.content).byteLength, 0))
const snapshot = computed(() => JSON.stringify({
  name: form.name, description: form.description, enabled: form.enabled,
  files: [...form.files].sort((a, b) => a.path.localeCompare(b.path)), entrypoint: form.entrypoint,
  parameterSchemaText: form.parameterSchemaText, supportsCheckMode: form.supportsCheckMode,
}))
const dirty = computed(() => editorVisible.value && baseline.value !== snapshot.value)
const canSave = computed(() => form.name.trim() !== '' && form.files.length > 0 && form.files.length <= 256 && totalBytes.value <= 10 * 1024 * 1024 && form.files.some((item) => item.path === form.entrypoint))

const treeNodes = computed<TreeNode[]>(() => {
  const roots: TreeNode[] = []
  const folders = new Map<string, TreeNode>()
  for (const file of [...form.files].sort((a, b) => a.path.localeCompare(b.path))) {
    const parts = file.path.split('/')
    let children = roots
    let prefix = ''
    parts.forEach((part, index) => {
      prefix = prefix ? `${prefix}/${part}` : part
      if (index === parts.length - 1) {
        children.push({ key: file.path, label: part, icon: 'pi pi-file', data: { path: file.path } })
        return
      }
      let folder = folders.get(prefix)
      if (!folder) {
        folder = { key: `folder:${prefix}`, label: part, icon: 'pi pi-folder', children: [] }
        folders.set(prefix, folder)
        children.push(folder)
      }
      children = folder.children ?? []
    })
  }
  return roots
})

const parameterDefinitions = computed<ParameterDefinition[]>(() => {
  const schema = selectedDetail.value?.parameterSchema
  const properties = schema?.properties
  if (!properties || typeof properties !== 'object' || Array.isArray(properties)) return []
  const required = new Set(Array.isArray(schema.required) ? schema.required.filter((item): item is string => typeof item === 'string') : [])
  return Object.entries(properties).flatMap(([name, value]) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return []
    const definition = value as Record<string, unknown>
    const type = definition.type
    if (!['string', 'integer', 'number', 'boolean'].includes(String(type))) return []
    return [{
      name,
      type: type as ParameterDefinition['type'],
      description: typeof definition.description === 'string' ? definition.description : '',
      required: required.has(name),
      sensitive: definition['x-ops-composer-sensitive'] === true,
      enumValues: Array.isArray(definition.enum) ? definition.enum : null,
      minimum: typeof definition.minimum === 'number' ? definition.minimum : undefined,
      maximum: typeof definition.maximum === 'number' ? definition.maximum : undefined,
      minLength: typeof definition.minLength === 'number' ? definition.minLength : undefined,
      maxLength: typeof definition.maxLength === 'number' ? definition.maxLength : undefined,
    }]
  })
})

function safeError(value: unknown): string {
  if (value instanceof ApiRequestError) {
    if (value.code === 'playbook_version_conflict' || value.code === 'version_conflict') return t('playbooks.versionConflict')
    if (value.code === 'playbook_source_disabled') return t('playbooks.sourceUnavailable')
    if (value.code === 'playbook_disabled') return t('playbooks.disabledRun')
    if (value.code === 'secret_parameters_required') return t('playbooks.secretParametersRequired')
  }
  return value instanceof Error ? value.message : t('common.failed')
}

function showError(value: unknown, summary = t('common.failed')): void {
  toast.add({ severity: 'error', summary, detail: safeError(value), life: 7000 })
}

function reference(playbook: PlaybookDto): PlaybookReferenceDto {
  if (playbook.source === 'DATABASE') {
    if (!playbook.playbookId) throw new Error(t('playbooks.choose'))
    return { source: 'DATABASE', playbookId: playbook.playbookId }
  }
  if (!playbook.path) throw new Error(t('playbooks.choose'))
  return { source: 'MOUNT', path: playbook.path }
}

function parseSchema(): Record<string, unknown> {
  const value: unknown = JSON.parse(form.parameterSchemaText)
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(t('playbooks.schemaInvalid'))
  return value as Record<string, unknown>
}

function payloadFromDetail(detail: DatabasePlaybookDto) {
  const base = { name: detail.name, description: detail.description, enabled: detail.enabled, supportsCheckMode: detail.supportsCheckMode }
  if (detail.revisionFormat === 'LEGACY_SINGLE_YAML') return { ...base, content: detail.content ?? '' }
  return {
    ...base,
    files: detail.files.map((item) => ({ path: item.path, content: item.content })),
    entrypoint: detail.entrypoint,
    parameterSchema: detail.parameterSchema,
  }
}

async function refreshPlaybooks(): Promise<void> {
  await queryClient.invalidateQueries({ queryKey: ['playbooks'] })
}

const validateMutation = useMutation({
  mutationFn: (input: PlaybookValidationDto) => api.validatePlaybook(input),
  onSuccess: (result) => {
    validationOutput.value = result.output
    toast.add({ severity: result.valid ? 'success' : 'error', summary: result.valid ? t('playbooks.valid') : t('playbooks.invalid'), detail: result.output.slice(-500), life: 7000 })
  },
  onError: (value) => showError(value, t('playbooks.invalid')),
})

const saveMutation = useMutation({
  mutationFn: () => {
    const payload = {
      name: form.name, description: form.description, enabled: form.enabled,
      files: form.files.map((item) => ({ ...item })), entrypoint: form.entrypoint,
      parameterSchema: parseSchema(), supportsCheckMode: form.supportsCheckMode,
    }
    return form.playbookId
      ? api.updateDatabasePlaybook(form.playbookId, { ...payload, version: form.version })
      : api.createDatabasePlaybook(payload)
  },
  onSuccess: async (detail) => {
    baseline.value = snapshot.value
    editorVisible.value = false
    selectedDetail.value = detail
    await refreshPlaybooks()
    toast.add({ severity: 'success', summary: t('common.saved'), life: 2500 })
  },
  onError: (value) => showError(value),
})

const toggleMutation = useMutation({
  mutationFn: async (playbook: PlaybookDto) => {
    if (!playbook.playbookId) throw new Error(t('playbooks.readOnlyMount'))
    const detail = await api.databasePlaybook(playbook.playbookId)
    return api.updateDatabasePlaybook(playbook.playbookId, { ...payloadFromDetail(detail), enabled: !detail.enabled, version: detail.version ?? 1 })
  },
  onSuccess: async (result) => {
    await refreshPlaybooks()
    toast.add({ severity: 'success', summary: result.enabled ? t('playbooks.enabled') : t('playbooks.disabled'), life: 2500 })
  },
  onError: (value) => showError(value),
})

const previewMutation = useMutation({
  mutationFn: () => api.previewPlaybookRun(runPayload()),
  onSuccess: (result) => { preview.value = result },
  onError: (value) => showError(value, t('playbooks.previewFailed')),
})

const executeMutation = useMutation({
  mutationFn: () => api.createPlaybookRun(runPayload()),
  onSuccess: (run) => {
    clearRunSecrets()
    void router.push({ name: 'run-detail', params: { id: run.runId } })
  },
  onError: (value) => {
    if (value instanceof ApiRequestError && value.code === 'host_key_confirmation_required') {
      toast.add({ severity: 'warn', summary: t('playbooks.runFailed'), detail: t('hosts.confirmationRequiredRun'), life: 8000 })
      return
    }
    showError(value, t('playbooks.runFailed'))
  },
})

const diffMutation = useMutation({
  mutationFn: (input: { revision: number; against: number }) => {
    if (!form.playbookId) throw new Error(t('playbooks.choose'))
    return api.diffPlaybookRevisions(form.playbookId, input.revision, input.against)
  },
  onSuccess: (result) => { diff.value = result; diffVisible.value = true },
  onError: (value) => showError(value),
})

const restoreMutation = useMutation({
  mutationFn: (revision: number) => {
    if (!form.playbookId) throw new Error(t('playbooks.choose'))
    return api.restorePlaybookRevision(form.playbookId, revision, form.version)
  },
  onSuccess: async (detail) => {
    loadDetail(detail)
    await loadRevisions()
    await refreshPlaybooks()
    toast.add({ severity: 'success', summary: t('playbooks.restored'), life: 3000 })
  },
  onError: (value) => showError(value),
})

function runPayload(): PlaybookRunDto {
  if (!selected.value) throw new Error(t('playbooks.choose'))
  let parameters: Record<string, unknown> = { ...runParameters }
  if (selected.value.source === 'MOUNT' || selectedDetail.value?.revisionFormat === 'LEGACY_SINGLE_YAML') {
    const parsed: unknown = JSON.parse(mountParametersText.value)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(t('playbooks.extraVarsInvalid'))
    parameters = parsed as Record<string, unknown>
  }
  return {
    target: { kind: target.value.kind, hostIds: target.value.hostIds, groupId: target.value.groupId },
    playbook: reference(selected.value), parameters, checkMode: checkMode.value,
    tags: tagsText.value.split(',').map((item) => item.trim()).filter(Boolean),
    skipTags: skipTagsText.value.split(',').map((item) => item.trim()).filter(Boolean),
    timeoutSeconds: timeoutSeconds.value, forks: forks.value,
  }
}

function resetEditor(values: Partial<typeof form>): void {
  Object.assign(form, {
    playbookId: null, name: '', description: '', enabled: true,
    files: [{ path: 'playbook.yml', content: DEFAULT_PLAYBOOK }], entrypoint: 'playbook.yml',
    parameterSchemaText: DEFAULT_SCHEMA, supportsCheckMode: false, version: 1,
    ...values,
  })
  activePath.value = form.entrypoint
  selectionKeys.value = { [activePath.value]: true }
  validationOutput.value = ''
  baseline.value = snapshot.value
}

function newPlaybook(): void {
  resetEditor({})
  revisions.value = []
  editorVisible.value = true
}

function loadDetail(detail: DatabasePlaybookDto): void {
  const files = detail.revisionFormat === 'PROJECT'
    ? detail.files.map((item) => ({ path: item.path, content: item.content }))
    : [{ path: 'playbook.yml', content: detail.content ?? DEFAULT_PLAYBOOK }]
  resetEditor({
    playbookId: detail.playbookId ?? null, name: detail.name, description: detail.description,
    enabled: detail.enabled, files, entrypoint: detail.entrypoint ?? 'playbook.yml',
    parameterSchemaText: JSON.stringify(detail.parameterSchema, null, 2),
    supportsCheckMode: detail.supportsCheckMode, version: detail.version ?? 1,
  })
  selectedDetail.value = detail
}

async function editPlaybook(playbook: PlaybookDto): Promise<void> {
  if (!playbook.playbookId) return
  try {
    const detail = await api.databasePlaybook(playbook.playbookId)
    loadDetail(detail)
    editorVisible.value = true
    await loadRevisions()
  } catch (value) { showError(value) }
}

async function loadRevisions(): Promise<void> {
  if (!form.playbookId) return
  revisionsLoading.value = true
  try { revisions.value = await api.playbookRevisions(form.playbookId) }
  finally { revisionsLoading.value = false }
}

function selectNode(node: TreeNode): void {
  const path = (node.data as { path?: string } | undefined)?.path
  if (path) activePath.value = path
}

function updateActiveContent(value: string | undefined): void {
  if (activeFile.value) activeFile.value.content = value ?? ''
}

function addFile(): void {
  const path = newFilePath.value.trim()
  if (!path || form.files.some((item) => item.path.toLocaleLowerCase() === path.toLocaleLowerCase())) return
  form.files.push({ path, content: '' })
  activePath.value = path
  selectionKeys.value = { [path]: true }
  newFilePath.value = ''
}

function deleteActiveFile(): void {
  if (!activeFile.value || form.files.length === 1) return
  const index = form.files.findIndex((item) => item.path === activePath.value)
  form.files.splice(index, 1)
  if (form.entrypoint === activePath.value) form.entrypoint = form.files[0]?.path ?? ''
  activePath.value = form.files[0]?.path ?? ''
  selectionKeys.value = activePath.value ? { [activePath.value]: true } : {}
}

function validateDraft(): void {
  try {
    validateMutation.mutate({
      files: form.files.map((item) => ({ ...item })), entrypoint: form.entrypoint,
      parameterSchema: parseSchema(), supportsCheckMode: form.supportsCheckMode,
    })
  } catch (value) { showError(value, t('playbooks.invalid')) }
}

function validateRow(playbook: PlaybookDto): void {
  validateMutation.mutate({ playbook: reference(playbook), supportsCheckMode: false })
}

async function importZip(event: { files: File[] }): Promise<void> {
  const file = event.files[0]
  if (!file) return
  try {
    const result = await api.importPlaybookZip(file, form.entrypoint || undefined)
    form.files = result.files.map((item) => ({ path: item.path, content: item.content }))
    form.entrypoint = result.entrypoint
    activePath.value = result.entrypoint
    selectionKeys.value = { [result.entrypoint]: true }
    toast.add({ severity: 'success', summary: t('playbooks.zipImported'), life: 3000 })
  } catch (value) { showError(value, t('playbooks.importFailed')) }
}

function removePlaybook(playbook: PlaybookDto): void {
  if (!playbook.playbookId || !playbook.version) return
  confirm.require({
    header: t('playbooks.deleteTitle'), message: t('playbooks.deleteConfirm', { name: playbook.name }),
    rejectProps: { label: t('common.cancel'), severity: 'secondary', outlined: true },
    acceptProps: { label: t('common.delete'), severity: 'danger' },
    accept: async () => {
      try { await api.deleteDatabasePlaybook(playbook.playbookId as string, playbook.version as number); await refreshPlaybooks() }
      catch (value) { showError(value) }
    },
  })
}

async function openRun(playbook: PlaybookDto): Promise<void> {
  selected.value = playbook
  selectedDetail.value = null
  if (playbook.source === 'DATABASE' && playbook.playbookId) {
    try { selectedDetail.value = await api.databasePlaybook(playbook.playbookId) }
    catch (value) { showError(value); return }
  }
  for (const key of Object.keys(runParameters)) delete runParameters[key]
  const schema = selectedDetail.value?.parameterSchema
  if (schema?.properties && typeof schema.properties === 'object' && !Array.isArray(schema.properties)) {
    for (const [name, raw] of Object.entries(schema.properties)) {
      if (raw && typeof raw === 'object' && !Array.isArray(raw) && 'default' in raw) runParameters[name] = (raw as Record<string, unknown>).default
    }
  }
  mountParametersText.value = '{}'
  tagsText.value = ''; skipTagsText.value = ''; checkMode.value = false; preview.value = null
  executeVisible.value = true
}

function clearRunSecrets(): void {
  for (const definition of parameterDefinitions.value) {
    if (definition.sensitive) delete runParameters[definition.name]
  }
}

function setRunParameter(name: string, value: unknown): void {
  runParameters[name] = value
}

function requestEditorClose(): void {
  if (!dirty.value || window.confirm(t('playbooks.unsavedConfirm'))) editorVisible.value = false
}

function compareRevision(item: PlaybookRevisionDto): void {
  const older = revisions.value.find((candidate) => candidate.revision < item.revision)
  if (older) diffMutation.mutate({ revision: item.revision, against: older.revision })
}

function restoreRevision(item: PlaybookRevisionDto): void {
  confirm.require({
    header: t('playbooks.restore'), message: t('playbooks.restoreConfirm', { revision: item.revision }),
    rejectProps: { label: t('common.cancel'), severity: 'secondary', outlined: true },
    acceptProps: { label: t('playbooks.restore') }, accept: () => restoreMutation.mutate(item.revision),
  })
}

async function exportRevision(item: PlaybookRevisionDto): Promise<void> {
  if (!form.playbookId) return
  try {
    const blob = await api.exportPlaybookZip(form.playbookId, item.revision)
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = `${form.name}-r${item.revision}.zip`; anchor.click(); URL.revokeObjectURL(url)
  } catch (value) { showError(value) }
}

function formatSize(bytes: number): string { return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(bytes < 10240 ? 1 : 0)} KiB` }
function formatDate(value: string): string { return new Intl.DateTimeFormat(locale.value, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) }

onBeforeRouteLeave(() => !dirty.value || window.confirm(t('playbooks.unsavedConfirm')))
</script>

<template>
  <div class="page-stack">
    <PageHeader :title="t('playbooks.title')" :description="t('playbooks.description')">
      <Button v-if="configQuery.data.value?.databaseWritable && canWrite" icon="pi pi-plus" :label="t('playbooks.create')" @click="newPlaybook" />
    </PageHeader>
    <Message v-if="configQuery.data.value" severity="info" :closable="false">{{ t('playbooks.sourceModeHint', { mode: t(`playbooks.mode.${configQuery.data.value.sourceMode}`) }) }}</Message>
    <section class="surface-card">
      <div class="table-toolbar"><Select v-model="sourceFilter" :options="sourceOptions" option-label="label" option-value="value" :aria-label="t('playbooks.sourceFilter')" /><Button icon="pi pi-refresh" severity="secondary" outlined :aria-label="t('common.refresh')" :loading="playbooksQuery.isFetching.value" @click="playbooksQuery.refetch()" /></div>
      <DataTable :value="playbooks" :loading="playbooksQuery.isPending.value" data-key="referenceKey" paginator :rows="10" striped-rows :table-props="{ 'aria-label': t('playbooks.title') }">
        <Column field="source" :header="t('playbooks.source')"><template #body="{ data }"><Tag :icon="data.source === 'DATABASE' ? 'pi pi-database' : 'pi pi-folder'" :severity="data.source === 'DATABASE' ? 'info' : 'secondary'" :value="data.source === 'DATABASE' ? t('playbooks.databaseSource') : t('playbooks.readOnlyMount')" /></template></Column>
        <Column field="name" :header="t('playbooks.name')" sortable><template #body="{ data }"><div class="table-primary"><strong>{{ data.name }}</strong><small>{{ data.entrypoint || data.path || data.description }}</small></div></template></Column>
        <Column field="revisionFormat" :header="t('playbooks.format')"><template #body="{ data }"><Tag :value="t(`playbooks.formats.${data.revisionFormat}`)" severity="secondary" /></template></Column>
        <Column field="enabled" :header="t('common.status')"><template #body="{ data }"><Tag :severity="data.enabled ? 'success' : 'secondary'" :value="data.enabled ? t('status.ENABLED') : t('status.DISABLED')" /></template></Column>
        <Column field="revision" :header="t('playbooks.revision')"><template #body="{ data }"><span v-if="data.revision">r{{ data.revision }}</span><code v-else>{{ data.sha256?.slice(0, 12) ?? '—' }}</code></template></Column>
        <Column field="size" :header="t('playbooks.size')"><template #body="{ data }">{{ formatSize(data.size ?? 0) }}</template></Column>
        <Column field="modifiedAt" :header="t('playbooks.updatedAt')"><template #body="{ data }">{{ formatDate(data.modifiedAt) }}</template></Column>
        <Column :header="t('common.actions')">
          <template #body="{ data }">
            <div class="row-actions">
              <Button icon="pi pi-check-circle" text rounded :aria-label="t('playbooks.validate')" @click="validateRow(data)" />
              <template v-if="data.source === 'DATABASE' && canWrite"><Button icon="pi pi-pencil" text rounded :aria-label="t('common.edit')" @click="editPlaybook(data)" /><Button :icon="data.enabled ? 'pi pi-pause' : 'pi pi-check'" text rounded :aria-label="data.enabled ? t('playbooks.disable') : t('playbooks.enable')" @click="toggleMutation.mutate(data)" /><Button icon="pi pi-trash" severity="danger" text rounded :aria-label="t('common.delete')" @click="removePlaybook(data)" /></template>
              <Button v-if="canRun" icon="pi pi-play" :label="t('playbooks.run')" text size="small" :disabled="!data.enabled" @click="openRun(data)" />
            </div>
          </template>
        </Column>
        <template #empty><div class="empty-state compact-empty"><i class="pi pi-folder-open" /><h3>{{ t('playbooks.empty') }}</h3><p>{{ t('playbooks.emptyHint') }}</p></div></template>
      </DataTable>
    </section>

    <Dialog :visible="editorVisible" modal maximizable :header="form.playbookId ? t('playbooks.editTitle', { name: form.name }) : t('playbooks.createTitle')" :style="{ width: 'min(1280px, 98vw)' }" @update:visible="!$event && requestEditorClose()">
      <Tabs value="files" class="playbook-project-tabs">
        <TabList><Tab value="files">{{ t('playbooks.files') }}</Tab><Tab value="settings">{{ t('playbooks.projectSettings') }}</Tab><Tab v-if="form.playbookId" value="history">{{ t('playbooks.history') }}</Tab></TabList>
        <TabPanels>
          <TabPanel value="files">
            <Splitter class="project-splitter">
              <SplitterPanel :size="28" :min-size="20"><div class="file-tree-panel"><div class="file-add-row"><InputText v-model="newFilePath" :placeholder="t('playbooks.newFilePath')" @keyup.enter="addFile" /><Button icon="pi pi-plus" :aria-label="t('playbooks.addFile')" @click="addFile" /></div><Tree v-model:selection-keys="selectionKeys" :value="treeNodes" selection-mode="single" :aria-label="t('playbooks.files')" @node-select="selectNode" /><Button icon="pi pi-trash" severity="danger" text :label="t('playbooks.deleteFile')" :disabled="form.files.length <= 1 || !activeFile" @click="deleteActiveFile" /></div></SplitterPanel>
              <SplitterPanel :size="72" :min-size="40"><div class="project-editor-panel"><div class="field-heading"><strong><code>{{ activePath }}</code></strong><small>{{ t('playbooks.projectLimits', { files: form.files.length, bytes: totalBytes }) }}</small></div><Textarea :model-value="activeFile?.content ?? ''" rows="25" class="code-input playbook-editor" spellcheck="false" :disabled="!activeFile" @update:model-value="updateActiveContent" /></div></SplitterPanel>
            </Splitter>
          </TabPanel>
          <TabPanel value="settings">
            <Fluid>
              <div class="form-grid two-columns">
                <div class="field"><label for="project-name">{{ t('playbooks.name') }}</label><InputText id="project-name" v-model="form.name" required maxlength="128" /></div>
                <div class="field"><label for="project-entrypoint">{{ t('playbooks.entrypoint') }}</label><Select id="project-entrypoint" v-model="form.entrypoint" :options="form.files.map((item) => item.path).filter((path) => /\.ya?ml$/i.test(path))" /></div>
                <div class="field span-2"><label for="project-description">{{ t('common.description') }}</label><InputText id="project-description" v-model="form.description" maxlength="1024" /></div>
                <label class="switch-field" for="project-enabled"><ToggleSwitch id="project-enabled" v-model="form.enabled" /><span>{{ t('playbooks.enabledField') }}</span></label>
                <label class="switch-field" for="project-check"><ToggleSwitch id="project-check" v-model="form.supportsCheckMode" /><span>{{ t('playbooks.supportsCheckMode') }}</span></label>
                <div class="field span-2"><label for="parameter-schema">{{ t('playbooks.parameterSchema') }}</label><Textarea id="parameter-schema" v-model="form.parameterSchemaText" rows="16" class="code-input" spellcheck="false" /><small>{{ t('playbooks.schemaHint') }}</small></div>
                <div class="field span-2"><label>{{ t('playbooks.zip') }}</label><FileUpload mode="basic" name="projectZip" accept=".zip,application/zip" :max-file-size="12582912" custom-upload :auto="false" :choose-label="t('playbooks.importZip')" @select="importZip" /><small>{{ t('playbooks.zipHint') }}</small></div>
              </div>
            </Fluid>
          </TabPanel>
          <TabPanel v-if="form.playbookId" value="history">
            <DataTable :value="revisions" :loading="revisionsLoading" data-key="revision" striped-rows><Column field="revision" :header="t('playbooks.revision')"><template #body="{ data }">r{{ data.revision }}</template></Column><Column field="revisionFormat" :header="t('playbooks.format')"><template #body="{ data }">{{ t(`playbooks.formats.${data.revisionFormat}`) }}</template></Column><Column field="sizeBytes" :header="t('playbooks.size')"><template #body="{ data }">{{ formatSize(data.sizeBytes) }}</template></Column><Column field="createdAt" :header="t('common.createdAt')"><template #body="{ data }">{{ formatDate(data.createdAt) }}</template></Column><Column :header="t('common.actions')"><template #body="{ data }"><div class="row-actions"><Button icon="pi pi-code" text rounded :disabled="data.revision <= 1" :aria-label="t('playbooks.diff')" @click="compareRevision(data)" /><Button icon="pi pi-download" text rounded :aria-label="t('playbooks.exportZip')" @click="exportRevision(data)" /><Button v-if="canWrite" icon="pi pi-undo" text rounded :aria-label="t('playbooks.restore')" @click="restoreRevision(data)" /></div></template></Column></DataTable>
          </TabPanel>
        </TabPanels>
      </Tabs>
      <Message v-if="validationOutput" severity="secondary" :closable="false"><pre class="validation-output">{{ validationOutput }}</pre></Message>
      <template #footer><Button :label="t('common.cancel')" severity="secondary" text @click="requestEditorClose" /><Button icon="pi pi-check-circle" :label="t('playbooks.validate')" severity="secondary" outlined :loading="validateMutation.isPending.value" :disabled="!canSave" @click="validateDraft" /><Button icon="pi pi-save" :label="t('common.save')" :loading="saveMutation.isPending.value" :disabled="!canSave" @click="saveMutation.mutate(undefined)" /></template>
    </Dialog>

    <Dialog v-model:visible="executeVisible" modal :header="t('playbooks.runTitle', { name: selected?.name ?? '' })" :style="{ width: 'min(960px, 96vw)' }" @hide="clearRunSecrets">
      <Fluid>
        <form id="playbook-run-form" class="form-grid two-columns" @submit.prevent="executeMutation.mutate()">
          <Message class="span-2" severity="info" :closable="false">{{ selected?.source === 'DATABASE' ? t('playbooks.pinnedRevision', { revision: selected?.revision }) : t('playbooks.mountedHash', { hash: selected?.sha256.slice(0, 12) }) }}</Message>
          <div class="span-2"><TargetPicker v-model="target" /></div>
          <template v-if="parameterDefinitions.length">
            <div v-for="definition in parameterDefinitions" :key="definition.name" class="field">
              <label :for="`parameter-${definition.name}`">{{ definition.name }}<span v-if="definition.required"> *</span></label>
              <Select v-if="definition.enumValues" :id="`parameter-${definition.name}`" v-model="runParameters[definition.name]" :options="definition.enumValues" />
              <ToggleSwitch v-else-if="definition.type === 'boolean'" :id="`parameter-${definition.name}`" :model-value="Boolean(runParameters[definition.name])" @update:model-value="setRunParameter(definition.name, $event)" />
              <InputNumber v-else-if="definition.type === 'integer' || definition.type === 'number'" :id="`parameter-${definition.name}`" :model-value="typeof runParameters[definition.name] === 'number' ? runParameters[definition.name] as number : null" :min="definition.minimum" :max="definition.maximum" :min-fraction-digits="0" :max-fraction-digits="definition.type === 'number' ? 8 : 0" @update:model-value="setRunParameter(definition.name, $event)" />
              <Password v-else-if="definition.sensitive" :id="`parameter-${definition.name}`" :model-value="String(runParameters[definition.name] ?? '')" :feedback="false" toggle-mask autocomplete="new-password" @update:model-value="setRunParameter(definition.name, $event)" />
              <InputText v-else :id="`parameter-${definition.name}`" :model-value="String(runParameters[definition.name] ?? '')" :minlength="definition.minLength" :maxlength="definition.maxLength" @update:model-value="setRunParameter(definition.name, $event)" />
              <small>{{ definition.description }}<span v-if="definition.sensitive"> · {{ t('playbooks.sensitiveHint') }}</span></small>
            </div>
          </template>
          <div v-else class="field span-2"><label for="mount-vars">{{ t('playbooks.extraVars') }}</label><Textarea id="mount-vars" v-model="mountParametersText" rows="7" class="code-input" /></div>
          <label class="switch-field" for="run-check-mode"><ToggleSwitch id="run-check-mode" v-model="checkMode" :disabled="!selected?.supportsCheckMode" /><span>{{ t('playbooks.checkMode') }}</span></label>
          <div class="field"><label for="tags">{{ t('playbooks.tags') }}</label><InputText id="tags" v-model="tagsText" :placeholder="t('playbooks.tagsHint')" /></div>
          <div class="field"><label for="skip-tags">{{ t('playbooks.skipTags') }}</label><InputText id="skip-tags" v-model="skipTagsText" :placeholder="t('playbooks.tagsHint')" /></div>
          <div class="field"><label for="playbook-timeout">{{ t('commands.timeout') }}</label><InputNumber id="playbook-timeout" v-model="timeoutSeconds" :min="1" :max="86400" suffix=" s" /></div>
          <div class="field"><label for="playbook-forks">{{ t('commands.forks') }}</label><InputNumber id="playbook-forks" v-model="forks" :min="1" :max="20" /></div>
          <Message v-if="preview" class="span-2" severity="success" :closable="false">{{ t('playbooks.previewSummary', { targets: preview.targetCount, revision: preview.revision ?? preview.digest.slice(0, 12), sensitive: preview.sensitiveParameters.length }) }}</Message>
        </form>
      </Fluid>
      <template #footer><Button :label="t('common.cancel')" severity="secondary" text @click="executeVisible = false" /><Button icon="pi pi-eye" :label="t('playbooks.preview')" severity="secondary" outlined :loading="previewMutation.isPending.value" @click="previewMutation.mutate()" /><Button type="submit" form="playbook-run-form" icon="pi pi-play" :label="t('playbooks.run')" :loading="executeMutation.isPending.value" /></template>
    </Dialog>

    <Dialog v-model:visible="diffVisible" modal :header="t('playbooks.diffTitle', { revision: diff?.revision, against: diff?.againstRevision })" :style="{ width: 'min(1100px, 97vw)' }"><div v-if="diff" class="diff-summary"><Tag severity="success" :value="t('playbooks.addedFiles', { count: diff.added.length })" /><Tag severity="danger" :value="t('playbooks.deletedFiles', { count: diff.deleted.length })" /><Tag severity="warn" :value="t('playbooks.modifiedFiles', { count: diff.modified.length })" /></div><pre class="revision-diff">{{ diff?.diff || t('playbooks.noDiff') }}</pre></Dialog>
  </div>
</template>
