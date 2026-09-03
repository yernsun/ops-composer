<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import Fluid from 'primevue/fluid'
import MultiSelect from 'primevue/multiselect'
import Select from 'primevue/select'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

import { api } from '@/shared/api/client'

export interface TargetValue {
  kind: 'ALL' | 'HOSTS' | 'GROUP'
  hostIds: string[]
  groupId: string | null
}

const model = defineModel<TargetValue>({ required: true })
const { t } = useI18n()
const hostsQuery = useQuery({ queryKey: ['hosts'], queryFn: api.hosts })
const groupsQuery = useQuery({ queryKey: ['groups'], queryFn: api.groups })
const kinds = computed(() => [
  { value: 'ALL', label: t('targets.all') },
  { value: 'HOSTS', label: t('targets.hosts') },
  { value: 'GROUP', label: t('targets.group') },
])
</script>

<template>
  <Fluid>
    <div class="form-grid target-picker">
      <div class="field">
        <label for="target-kind">{{ t('targets.kind') }}</label>
        <Select
          id="target-kind"
          v-model="model.kind"
          :options="kinds"
          option-label="label"
          option-value="value"
        />
      </div>
      <div v-if="model.kind === 'HOSTS'" class="field">
        <label for="target-hosts">{{ t('targets.hosts') }}</label>
        <MultiSelect
          id="target-hosts"
          v-model="model.hostIds"
          :options="hostsQuery.data.value ?? []"
          option-label="name"
          option-value="hostId"
          display="chip"
          filter
          :placeholder="t('targets.chooseHosts')"
        />
      </div>
      <div v-if="model.kind === 'GROUP'" class="field">
        <label for="target-group">{{ t('targets.group') }}</label>
        <Select
          id="target-group"
          v-model="model.groupId"
          :options="groupsQuery.data.value ?? []"
          option-label="name"
          option-value="groupId"
          filter
          :placeholder="t('targets.chooseGroup')"
        />
      </div>
    </div>
  </Fluid>
</template>
