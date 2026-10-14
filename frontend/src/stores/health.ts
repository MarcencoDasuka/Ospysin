import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { http } from '@/api/http'
import type { HealthResponse } from '@/api/types'

export const useHealthStore = defineStore('health', () => {
  const health = ref<HealthResponse | null>(null)
  const loading = ref(false)
  const error = ref(false)

  const isDatabaseUp = computed(() => health.value?.components?.database === 'UP')
  const isOllamaReady = computed(() => health.value?.components?.ollama === 'UP')
  const isSystemUp = computed(() => health.value?.status === 'UP')

  const ollamaStatusText = computed(() => {
    return isOllamaReady.value ? 'Ollama: READY' : 'Ollama: OFFLINE'
  })

  async function checkHealth(): Promise<HealthResponse | null> {
    loading.value = true
    error.value = false
    try {
      const response = await http.get<HealthResponse>('/health')
      health.value = response.data
      return response.data
    } catch {
      error.value = true
      health.value = {
        status: 'DOWN',
        components: {
          database: 'DOWN',
          ollama: 'DOWN'
        }
      }
      return null
    } finally {
      loading.value = false
    }
  }

  return {
    health,
    loading,
    error,
    isDatabaseUp,
    isOllamaReady,
    isSystemUp,
    ollamaStatusText,
    checkHealth
  }
})
