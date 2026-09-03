<script setup lang="ts">
import Tag from 'primevue/tag'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps<{ status: string }>()
const { t, te } = useI18n()
const severity = computed(() => {
  const value = props.status.toUpperCase()
  if (['SUCCEEDED', 'ACTIVE', 'ENABLED'].includes(value)) return 'success'
  if (['FAILED', 'REJECTED', 'UNREACHABLE', 'TIMED_OUT'].includes(value)) return 'danger'
  if (['PARTIAL', 'INTERRUPTED', 'CANCELED'].includes(value)) return 'warn'
  if (['RUNNING', 'PREPARING'].includes(value)) return 'info'
  return 'secondary'
})
const label = computed(() => {
  const key = `status.${props.status.toUpperCase()}`
  return te(key) ? t(key) : props.status
})
</script>

<template>
  <Tag :value="label" :severity="severity" rounded />
</template>
