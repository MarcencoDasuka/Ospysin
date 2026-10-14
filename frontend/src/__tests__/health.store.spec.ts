import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useHealthStore } from '@/stores/health'
import { http } from '@/api/http'
import type { HealthResponse } from '@/api/types'

describe('Pinia Health Store (useHealthStore)', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('initializes with default empty state', () => {
    const store = useHealthStore()
    expect(store.health).toBeNull()
    expect(store.loading).toBe(false)
    expect(store.error).toBe(false)
    expect(store.isOllamaReady).toBe(false)
    expect(store.isDatabaseUp).toBe(false)
    expect(store.isSystemUp).toBe(false)
    expect(store.ollamaStatusText).toBe('Ollama: OFFLINE')
  })

  it('updates state and getters when health check succeeds with all components UP', async () => {
    const mockHealth: HealthResponse = {
      status: 'UP',
      components: {
        database: 'UP',
        ollama: 'UP'
      }
    }

    vi.spyOn(http, 'get').mockResolvedValueOnce({
      data: mockHealth,
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {} as any
    })

    const store = useHealthStore()
    const result = await store.checkHealth()

    expect(result).toEqual(mockHealth)
    expect(store.health).toEqual(mockHealth)
    expect(store.loading).toBe(false)
    expect(store.error).toBe(false)
    expect(store.isOllamaReady).toBe(true)
    expect(store.isDatabaseUp).toBe(true)
    expect(store.isSystemUp).toBe(true)
    expect(store.ollamaStatusText).toBe('Ollama: READY')
  })

  it('identifies when Ollama is DOWN but overall system/database is UP', async () => {
    const mockHealth: HealthResponse = {
      status: 'UP',
      components: {
        database: 'UP',
        ollama: 'DOWN'
      }
    }

    vi.spyOn(http, 'get').mockResolvedValueOnce({
      data: mockHealth,
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {} as any
    })

    const store = useHealthStore()
    await store.checkHealth()

    expect(store.isOllamaReady).toBe(false)
    expect(store.isDatabaseUp).toBe(true)
    expect(store.ollamaStatusText).toBe('Ollama: OFFLINE')
  })

  it('handles backend connection failure gracefully and sets fallback DOWN state', async () => {
    vi.spyOn(http, 'get').mockRejectedValueOnce(new Error('Connection refused'))

    const store = useHealthStore()
    const result = await store.checkHealth()

    expect(result).toBeNull()
    expect(store.loading).toBe(false)
    expect(store.error).toBe(true)
    expect(store.health).toEqual({
      status: 'DOWN',
      components: {
        database: 'DOWN',
        ollama: 'DOWN'
      }
    })
    expect(store.isOllamaReady).toBe(false)
    expect(store.isDatabaseUp).toBe(false)
    expect(store.isSystemUp).toBe(false)
    expect(store.ollamaStatusText).toBe('Ollama: OFFLINE')
  })
})
