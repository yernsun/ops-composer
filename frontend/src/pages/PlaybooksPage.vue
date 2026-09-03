<script setup lang="ts">
import { useMutation, useQuery } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Card from 'primevue/card'
import Dialog from 'primevue/dialog'
import Fluid from 'primevue/fluid'
import InputNumber from 'primevue/inputnumber'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import Skeleton from 'primevue/skeleton'
import Textarea from 'primevue/textarea'
import { useToast } from 'primevue/usetoast'
import { reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'

import PageHeader from '@/components/PageHeader.vue'
import TargetPicker, { type TargetValue } from '@/components/TargetPicker.vue'
import { api, type PlaybookDto } from '@/shared/api/client'

const { t } = useI18n()
const router = useRouter()
const toast = useToast()
const executeVisible = ref(false)
const selected = ref<PlaybookDto | null>(null)
const target = reactive<TargetValue>({ kind: 'ALL', hostIds: [], groupId: null })
const extraVarsText = ref('{}')
const tagsText = ref('')
const skipTagsText = ref('')
const timeoutSeconds = ref(1800)
const forks = ref(5)
const playbooksQuery = useQuery({ queryKey: ['playbooks'], queryFn: api.playbooks })
const validateMutation = useMutation({
  mutationFn: api.validatePlaybook,
  onSuccess: (result) =>
    toast.add({
      severity: result.valid ? 'success' : 'error',
      summary: result.valid ? t('playbooks.valid') : t('playbooks.invalid'),
      detail: result.output.slice(-400),
      life: 6000,
    }),
})
const executeMutation = useMutation({
  mutationFn: async () => {
    if (!selected.value) throw new Error(t('playbooks.choose'))
    let extraVars: Record<string, unknown>
    try {
      extraVars = JSON.parse(extraVarsText.value) as Record<string, unknown>
    } catch {
      throw new Error(t('playbooks.extraVarsInvalid'))
    }
    const split = (value: string) =>
      value.split(',').map((item) => item.trim()).filter(Boolean)
    return api.createPlaybookRun({
      target: {
        kind: target.kind,
        hostIds: target.hostIds,
        groupId: target.groupId,
      },
      playbookPath: selected.value.path,
      extraVars,
      tags: split(tagsText.value),
      skipTags: split(skipTagsText.value),
      timeoutSeconds: timeoutSeconds.value,
      forks: forks.value,
    })
  },
  onSuccess: (run) => void router.push({ name: 'run-detail', params: { id: run.runId } }),
  onError: (error) =>
    toast.add({ severity: 'error', summary: t('playbooks.runFailed'), detail: error.message, life: 5000 }),
})

function openRun(playbook: PlaybookDto): void {
  selected.value = playbook
  extraVarsText.value = '{}'
  tagsText.value = ''
  skipTagsText.value = ''
  executeVisible.value = true
}
</script>

<template>
  <div class="page-stack">
    <PageHeader :title="t('playbooks.title')" :description="t('playbooks.description')">
      <Button icon="pi pi-refresh" severity="secondary" outlined :label="t('common.refresh')" :loading="playbooksQuery.isFetching.value" @click="playbooksQuery.refetch()" />
    </PageHeader>
    <Message severity="info" :closable="false"><i class="pi pi-lock" /> {{ t('playbooks.readOnlyHint') }}</Message>
    <section v-if="playbooksQuery.isPending.value" class="playbook-grid">
      <Skeleton v-for="index in 4" :key="index" height="14rem" border-radius="16px" />
    </section>
    <section v-else-if="playbooksQuery.data.value?.length" class="playbook-grid">
      <Card v-for="playbook in playbooksQuery.data.value" :key="playbook.path" class="playbook-card">
        <template #header><div class="playbook-icon"><i class="pi pi-book" /></div></template>
        <template #title>{{ playbook.name }}</template>
        <template #subtitle><code>{{ playbook.path }}</code></template>
        <template #content>
          <dl class="playbook-meta">
            <div><dt>{{ t('playbooks.revision') }}</dt><dd><code>{{ playbook.sha256.slice(0, 12) }}</code></dd></div>
            <div><dt>{{ t('playbooks.size') }}</dt><dd>{{ Math.ceil(playbook.size / 1024) }} KiB</dd></div>
          </dl>
        </template>
        <template #footer>
          <div class="card-actions">
            <Button :label="t('playbooks.validate')" icon="pi pi-check-circle" severity="secondary" outlined :loading="validateMutation.isPending.value" @click="validateMutation.mutate(playbook.path)" />
            <Button :label="t('playbooks.run')" icon="pi pi-play" @click="openRun(playbook)" />
          </div>
        </template>
      </Card>
    </section>
    <section v-else class="empty-state">
      <i class="pi pi-folder-open" />
      <h3>{{ t('playbooks.empty') }}</h3>
      <p>{{ t('playbooks.emptyHint') }}</p>
    </section>

    <Dialog v-model:visible="executeVisible" modal :header="t('playbooks.runTitle', { name: selected?.name ?? '' })" :style="{ width: 'min(900px, 96vw)' }">
      <Fluid>
        <form id="playbook-run-form" class="form-grid two-columns" @submit.prevent="executeMutation.mutate()">
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
