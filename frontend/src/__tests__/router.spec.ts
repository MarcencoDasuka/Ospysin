import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { router } from '@/router'
import { useAuthStore } from '@/stores/auth'
import { http } from '@/api/http'

describe('Vue Router Navigation Guards', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('triggers authStore.fetchCurrentUser() on cold start when authStore.status is idle', async () => {
    const authStore = useAuthStore()
    expect(authStore.status).toBe('idle')

    const fetchSpy = vi.spyOn(authStore, 'fetchCurrentUser').mockImplementation(async () => {
      authStore.status = 'unauthenticated'
      return null
    })

    await router.push('/')

    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(router.currentRoute.value.path).toBe('/login')
  })

  it('redirects unauthenticated user from protected route "/" to "/login"', async () => {
    const authStore = useAuthStore()
    authStore.status = 'unauthenticated'
    authStore.user = null

    // Mock http.get to prevent unexpected network calls
    vi.spyOn(http, 'get').mockRejectedValue(new Error('Unauthorized'))

    await router.push('/')

    expect(router.currentRoute.value.path).toBe('/login')
  })

  it('allows authenticated user to navigate to protected route "/"', async () => {
    const authStore = useAuthStore()
    authStore.status = 'authenticated'
    authStore.user = { id: 'admin-1', username: 'admin', role: 'ADMIN' }

    await router.push('/')

    expect(router.currentRoute.value.path).toBe('/')
  })

  it('redirects authenticated user from guestOnly route "/login" to "/"', async () => {
    const authStore = useAuthStore()
    authStore.status = 'authenticated'
    authStore.user = { id: 'admin-1', username: 'admin', role: 'ADMIN' }

    // First ensure we are at '/'
    await router.push('/')
    expect(router.currentRoute.value.path).toBe('/')

    // Attempt navigating to '/login'
    await router.push('/login')
    expect(router.currentRoute.value.path).toBe('/')
  })
})
