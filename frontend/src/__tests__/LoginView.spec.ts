import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createRouter, createMemoryHistory } from 'vue-router'
import LoginView from '@/views/LoginView.vue'
import { useAuthStore } from '@/stores/auth'
import { ApiError } from '@/api/http'
import type { ProblemDetail } from '@/api/types'

describe('Screen 0: Login View Component (LoginView.vue)', () => {
  let router: ReturnType<typeof createRouter>

  beforeEach(() => {
    setActivePinia(createPinia())
    router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: '/login', name: 'login', component: LoginView },
        { path: '/', name: 'home', component: { template: '<div>Home</div>' } },
        { path: '/sessions/:id', name: 'session', component: { template: '<div>Session</div>' } }
      ]
    })
  })

  function createWrapper() {
    return mount(LoginView, {
      global: {
        plugins: [router]
      }
    })
  }

  it('renders username, password inputs and sign-in button', () => {
    const wrapper = createWrapper()

    expect(wrapper.find('[data-testid="username-input"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="password-input"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="signin-button"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="error-callout"]').exists()).toBe(false)
  })

  it('disables the submit button when username or password is empty', async () => {
    const wrapper = createWrapper()
    const button = wrapper.find('[data-testid="signin-button"]')

    // Initially empty
    expect(button.attributes('disabled')).toBeDefined()

    // Fill only username
    await wrapper.find('[data-testid="username-input"]').setValue('admin')
    expect(button.attributes('disabled')).toBeDefined()

    // Fill password as well
    await wrapper.find('[data-testid="password-input"]').setValue('secret123')
    expect(button.attributes('disabled')).toBeUndefined()
  })

  it('disables inputs and submit button while authentication is in flight to prevent duplicate submission', async () => {
    const wrapper = createWrapper()
    const authStore = useAuthStore()

    // Set credentials
    await wrapper.find('[data-testid="username-input"]').setValue('admin')
    await wrapper.find('[data-testid="password-input"]').setValue('secret123')

    // Mock login to simulate a pending in-flight promise
    let resolveLogin: (value: any) => void = () => {}
    const loginPromise = new Promise((resolve) => {
      resolveLogin = resolve
    })

    vi.spyOn(authStore, 'login').mockImplementation(() => {
      authStore.status = 'loading'
      return loginPromise as any
    })

    // Trigger form submit
    await wrapper.find('form').trigger('submit.prevent')

    // Check loading/disabled state
    const button = wrapper.find('[data-testid="signin-button"]')
    expect(button.attributes('disabled')).toBeDefined()
    expect(button.text()).toContain('Authenticating...')
    expect(wrapper.find('[data-testid="username-input"]').attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-testid="password-input"]').attributes('disabled')).toBeDefined()

    // Resolve login
    resolveLogin({ id: '1', username: 'admin', role: 'ADMIN' })
    authStore.status = 'authenticated'
    await flushPromises()
  })

  it('displays RFC 9457 error callout with detail message on 401 Unauthorized', async () => {
    const wrapper = createWrapper()
    const authStore = useAuthStore()

    const problem: ProblemDetail = {
      type: 'https://ospysin.dev/errors/unauthorized',
      title: 'Authentication Failed',
      status: 401,
      detail: 'Invalid operator credentials provided'
    }

    vi.spyOn(authStore, 'login').mockImplementation(async () => {
      authStore.status = 'unauthenticated'
      authStore.error = problem
      throw new ApiError(problem)
    })

    await wrapper.find('[data-testid="username-input"]').setValue('admin')
    await wrapper.find('[data-testid="password-input"]').setValue('wrong-password')
    await wrapper.find('form').trigger('submit.prevent')
    await flushPromises()

    const errorBox = wrapper.find('[data-testid="error-callout"]')
    expect(errorBox.exists()).toBe(true)
    expect(errorBox.text()).toContain('Authentication Failed')
    expect(errorBox.text()).toContain('Invalid operator credentials provided')
  })

  it('displays field-level validation errors (invalidParams) on 422 Unprocessable Entity', async () => {
    const wrapper = createWrapper()
    const authStore = useAuthStore()

    const problem: ProblemDetail = {
      type: 'https://ospysin.dev/errors/validation-error',
      title: 'Invalid Request Parameters',
      status: 422,
      detail: 'Credentials did not satisfy validation constraints',
      invalidParams: [
        { name: 'username', reason: 'Must not be blank' },
        { name: 'password', reason: 'Must contain at least 8 characters' }
      ]
    }

    vi.spyOn(authStore, 'login').mockImplementation(async () => {
      authStore.status = 'unauthenticated'
      authStore.error = problem
      throw new ApiError(problem)
    })

    await wrapper.find('[data-testid="username-input"]').setValue('admin')
    await wrapper.find('[data-testid="password-input"]').setValue('short')
    await wrapper.find('form').trigger('submit.prevent')
    await flushPromises()

    const errorBox = wrapper.find('[data-testid="error-callout"]')
    expect(errorBox.exists()).toBe(true)

    const paramItems = wrapper.findAll('[data-testid="invalid-param-item"]')
    expect(paramItems).toHaveLength(2)
    expect(paramItems[0].text()).toContain('username: Must not be blank')
    expect(paramItems[1].text()).toContain('password: Must contain at least 8 characters')
  })

  it('navigates to "/" (home) upon successful operator authentication', async () => {
    const wrapper = createWrapper()
    const authStore = useAuthStore()
    const pushSpy = vi.spyOn(router, 'push')

    vi.spyOn(authStore, 'login').mockResolvedValueOnce({
      id: 'admin-1',
      username: 'admin',
      role: 'ADMIN'
    })

    await wrapper.find('[data-testid="username-input"]').setValue('admin')
    await wrapper.find('[data-testid="password-input"]').setValue('validPassword123')
    await wrapper.find('form').trigger('submit.prevent')
    await flushPromises()

    expect(authStore.login).toHaveBeenCalledWith({
      username: 'admin',
      password: 'validPassword123'
    })
    expect(pushSpy).toHaveBeenCalledWith('/')
  })

  it('clears existing auth error when component mounts', () => {
    const authStore = useAuthStore()
    authStore.error = { title: 'Stale Login Error' }
    expect(authStore.error).not.toBeNull()

    createWrapper()

    expect(authStore.error).toBeNull()
  })

  it('honors safe internal redirect query parameter upon successful login', async () => {
    await router.push('/login?redirect=/sessions/123')
    const wrapper = createWrapper()
    const authStore = useAuthStore()
    const pushSpy = vi.spyOn(router, 'push')

    vi.spyOn(authStore, 'login').mockResolvedValueOnce({
      id: 'admin-1',
      username: 'admin',
      role: 'ADMIN'
    })

    await wrapper.find('[data-testid="username-input"]').setValue('admin')
    await wrapper.find('[data-testid="password-input"]').setValue('validPassword123')
    await wrapper.find('form').trigger('submit.prevent')
    await flushPromises()

    expect(pushSpy).toHaveBeenCalledWith('/sessions/123')
  })

  it('rejects open redirects (such as "//evil.example" or external URLs) and defaults to "/"', async () => {
    await router.push('/login?redirect=//evil.example')
    const wrapper = createWrapper()
    const authStore = useAuthStore()
    const pushSpy = vi.spyOn(router, 'push')

    vi.spyOn(authStore, 'login').mockResolvedValueOnce({
      id: 'admin-1',
      username: 'admin',
      role: 'ADMIN'
    })

    await wrapper.find('[data-testid="username-input"]').setValue('admin')
    await wrapper.find('[data-testid="password-input"]').setValue('validPassword123')
    await wrapper.find('form').trigger('submit.prevent')
    await flushPromises()

    expect(pushSpy).toHaveBeenCalledWith('/')
  })
})
