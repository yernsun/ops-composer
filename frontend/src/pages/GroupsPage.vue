<script setup lang="ts">
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import Fluid from 'primevue/fluid'
import InputText from 'primevue/inputtext'
import MultiSelect from 'primevue/multiselect'
import Textarea from 'primevue/textarea'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import PageHeader from '@/components/PageHeader.vue'
import { api, type HostGroupDto } from '@/shared/api/client'

interface GroupForm {
  groupId: string | null
  name: string
  description: string
  variablesText: string
  hostIds: string[]
}

const { t } = useI18n()
const queryClient = useQueryClient()
const toast = useToast()
const confirm = useConfirm()
const visible = ref(false)
const form = reactive<GroupForm>({
  groupId: null,
  name: '',
  description: '',
  variablesText: '{}',
  hostIds: [],
})
const groupsQuery = useQuery({ queryKey: ['groups'], queryFn: api.groups })
const hostsQuery = useQuery({ queryKey: ['hosts'], queryFn: api.hosts })
const saveMutation = useMutation({
  mutationFn: async () => {
    let variables: Record<string, unknown>
    try {
      variables = JSON.parse(form.variablesText) as Record<string, unknown>
    } catch {
      throw new Error(t('groups.variablesInvalid'))
    }
    const payload = {
      name: form.name,
      description: form.description,
      variables,
      hostIds: form.hostIds,
    }
    return form.groupId
      ? api.updateGroup(form.groupId, payload)
      : api.createGroup(payload)
  },
  onSuccess: async () => {
    visible.value = false
    await queryClient.invalidateQueries({ queryKey: ['groups'] })
    toast.add({ severity: 'success', summary: t('common.saved'), life: 2500 })
  },
  onError: (error) =>
    toast.add({ severity: 'error', summary: t('common.failed'), detail: error.message, life: 5000 }),
})

function create(): void {
  Object.assign(form, {
    groupId: null,
    name: '',
    description: '',
    variablesText: '{}',
    hostIds: [],
  })
  visible.value = true
}

function edit(group: HostGroupDto): void {
  Object.assign(form, {
    groupId: group.groupId,
    name: group.name,
    description: group.description,
    variablesText: JSON.stringify(group.variables, null, 2),
    hostIds: [...group.hostIds],
  })
  visible.value = true
}

function remove(group: HostGroupDto): void {
  confirm.require({
    header: t('groups.deleteTitle'),
    message: t('groups.deleteConfirm', { name: group.name }),
    rejectProps: { label: t('common.cancel'), severity: 'secondary', outlined: true },
    acceptProps: { label: t('common.delete'), severity: 'danger' },
    accept: async () => {
      await api.deleteGroup(group.groupId)
      await queryClient.invalidateQueries({ queryKey: ['groups'] })
      toast.add({ severity: 'success', summary: t('common.deleted'), life: 2500 })
    },
  })
}
</script>

<template>
  <div class="page-stack">
    <PageHeader :title="t('groups.title')" :description="t('groups.description')">
      <Button icon="pi pi-plus" :label="t('groups.add')" @click="create" />
    </PageHeader>
    <section class="surface-card">
      <DataTable
        :value="groupsQuery.data.value ?? []"
        :loading="groupsQuery.isPending.value"
        data-key="groupId"
        paginator
        :rows="10"
        striped-rows
        state-storage="local"
        state-key="ops-composer-groups"
        :table-props="{ 'aria-label': t('groups.title') }"
      >
        <Column field="name" :header="t('groups.name')" sortable />
        <Column :header="t('groups.hostCount')" sortable>
          <template #body="{ data }">{{ data.hostIds.length }}</template>
        </Column>
        <Column field="description" :header="t('common.description')" />
        <Column :header="t('common.actions')">
          <template #body="{ data }">
            <div class="row-actions">
              <Button icon="pi pi-pencil" text rounded :aria-label="t('common.edit')" @click="edit(data)" />
              <Button icon="pi pi-trash" severity="danger" text rounded :aria-label="t('common.delete')" @click="remove(data)" />
            </div>
          </template>
        </Column>
        <template #empty>{{ t('groups.empty') }}</template>
      </DataTable>
    </section>

    <Dialog v-model:visible="visible" modal :header="form.groupId ? t('groups.edit') : t('groups.add')" :style="{ width: 'min(720px, 94vw)' }">
      <Fluid>
        <form id="group-form" class="form-grid" @submit.prevent="saveMutation.mutate()">
          <div class="field"><label for="group-name">{{ t('groups.name') }}</label><InputText id="group-name" v-model="form.name" required /></div>
          <div class="field"><label for="group-hosts">{{ t('groups.members') }}</label><MultiSelect id="group-hosts" v-model="form.hostIds" :options="hostsQuery.data.value ?? []" option-label="name" option-value="hostId" display="chip" filter /></div>
          <div class="field"><label for="group-description">{{ t('common.description') }}</label><Textarea id="group-description" v-model="form.description" auto-resize rows="2" /></div>
          <div class="field"><label for="group-variables">{{ t('groups.variables') }}</label><Textarea id="group-variables" v-model="form.variablesText" rows="6" class="code-input" /><small>{{ t('groups.variablesHint') }}</small></div>
        </form>
      </Fluid>
      <template #footer>
        <Button :label="t('common.cancel')" severity="secondary" text @click="visible = false" />
        <Button type="submit" form="group-form" :label="t('common.save')" icon="pi pi-check" :loading="saveMutation.isPending.value" />
      </template>
    </Dialog>
  </div>
</template>
