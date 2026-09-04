<script setup lang="ts">
import { useMutation } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Card from 'primevue/card'
import Fluid from 'primevue/fluid'
import InputNumber from 'primevue/inputnumber'
import Message from 'primevue/message'
import Select from 'primevue/select'
import SelectButton from 'primevue/selectbutton'
import Textarea from 'primevue/textarea'
import ToggleSwitch from 'primevue/toggleswitch'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'

import PageHeader from '@/components/PageHeader.vue'
import TargetPicker, { type TargetValue } from '@/components/TargetPicker.vue'
import { api } from '@/shared/api/client'

const { t } = useI18n()
const router = useRouter()
const toast = useToast()
const confirm = useConfirm()
const target = ref<TargetValue>({ kind: 'ALL', hostIds: [], groupId: null })
const mode = ref<'COMMAND' | 'SHELL'>('COMMAND')
const command = ref('')
const become = ref('CREDENTIAL_DEFAULT')
const timeoutSeconds = ref(60)
const forks = ref(5)
const shellAcknowledged = ref(false)
const modeOptions = computed(() => [
  { value: 'COMMAND', label: t('commands.commandMode'), icon: 'pi pi-shield' },
  { value: 'SHELL', label: t('commands.shellMode'), icon: 'pi pi-exclamation-triangle' },
])
const becomeOptions = computed(() => [
  { value: 'CREDENTIAL_DEFAULT', label: t('commands.becomeDefault') },
  { value: 'ENABLED', label: t('commands.becomeEnabled') },
  { value: 'DISABLED', label: t('commands.becomeDisabled') },
])

const runMutation = useMutation({
  mutationFn: (confirmed: boolean) =>
    api.createCommandRun({
      target: {
        kind: target.value.kind,
        hostIds: target.value.hostIds,
        groupId: target.value.groupId,
      },
      mode: mode.value,
      command: command.value,
      become: become.value,
      shellConfirmed: confirmed,
      timeoutSeconds: timeoutSeconds.value,
      forks: forks.value,
    }),
  onSuccess: (run) => void router.push({ name: 'run-detail', params: { id: run.runId } }),
  onError: (error) =>
    toast.add({ severity: 'error', summary: t('commands.createFailed'), detail: error.message, life: 5000 }),
})

function execute(): void {
  if (mode.value === 'SHELL') {
    if (!shellAcknowledged.value) {
      toast.add({ severity: 'warn', summary: t('commands.ackRequired'), life: 3500 })
      return
    }
    confirm.require({
      header: t('commands.shellConfirmTitle'),
      message: t('commands.shellConfirmMessage'),
      icon: 'pi pi-exclamation-triangle',
      rejectProps: { label: t('common.cancel'), severity: 'secondary', outlined: true },
      acceptProps: { label: t('commands.executeShell'), severity: 'danger' },
      accept: () => runMutation.mutate(true),
    })
    return
  }
  runMutation.mutate(false)
}
</script>

<template>
  <div class="page-stack">
    <PageHeader :title="t('commands.title')" :description="t('commands.description')" />
    <Card class="execution-card">
      <template #content>
        <Fluid>
          <form class="execution-layout" @submit.prevent="execute">
            <section class="execution-main">
              <h3>{{ t('commands.targetSection') }}</h3>
              <TargetPicker v-model="target" />
              <h3>{{ t('commands.commandSection') }}</h3>
              <div class="field">
                <label id="mode-label">{{ t('commands.mode') }}</label>
                <SelectButton
                  v-model="mode"
                  :options="modeOptions"
                  option-label="label"
                  option-value="value"
                  :allow-empty="false"
                  aria-labelledby="mode-label"
                >
                  <template #option="{ option }"><i :class="option.icon" />{{ option.label }}</template>
                </SelectButton>
              </div>
              <Message v-if="mode === 'SHELL'" severity="warn" :closable="false">
                {{ t('commands.shellWarning') }}
              </Message>
              <div class="field">
                <label for="command-text">{{ t('commands.command') }}</label>
                <Textarea
                  id="command-text"
                  v-model="command"
                  rows="7"
                  maxlength="4096"
                  class="code-input command-input"
                  :placeholder="mode === 'COMMAND' ? 'df -h' : 'journalctl -u docker | tail -n 100'"
                  required
                />
                <small>{{ command.length }} / 4096</small>
              </div>
              <label v-if="mode === 'SHELL'" class="switch-field" for="shell-ack">
                <ToggleSwitch id="shell-ack" v-model="shellAcknowledged" />
                <span>{{ t('commands.shellAcknowledge') }}</span>
              </label>
            </section>
            <aside class="execution-options">
              <h3>{{ t('commands.options') }}</h3>
              <div class="field"><label for="become">{{ t('commands.become') }}</label><Select id="become" v-model="become" :options="becomeOptions" option-label="label" option-value="value" /></div>
              <div class="field"><label for="timeout">{{ t('commands.timeout') }}</label><InputNumber id="timeout" v-model="timeoutSeconds" :min="1" :max="900" suffix=" s" /></div>
              <div class="field"><label for="forks">{{ t('commands.forks') }}</label><InputNumber id="forks" v-model="forks" :min="1" :max="20" /></div>
              <Button
                type="submit"
                icon="pi pi-play"
                :label="t('commands.execute')"
                :severity="mode === 'SHELL' ? 'danger' : 'primary'"
                :loading="runMutation.isPending.value"
                :disabled="!command.trim()"
              />
              <p class="options-note"><i class="pi pi-info-circle" />{{ t('commands.queueNote') }}</p>
            </aside>
          </form>
        </Fluid>
      </template>
    </Card>
  </div>
</template>
