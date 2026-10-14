import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { setActivePinia, createPinia } from 'pinia'
import NewSessionModal from '@/components/NewSessionModal.vue'
import { useSessionsStore } from '@/stores/sessions'
import { http, ApiError } from '@/api/http'
import {
  CANONICAL_SCOPE_ACK_VERSION,
  CANONICAL_SCOPE_ACK_STATEMENT,
  type AuditSession,
  type ProblemDetail
} from '@/api/types'

describe('Screen 2: New Session Setup Modal Component (NewSessionModal.vue)', () => {
  const mockCreatedSession: AuditSession = {
    id: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
    targetUrl: 'https://example.com',
    mode: 'PUBLIC',
    state: 'ACTIVE',
    scopeAcknowledged: true,
    scopeAckVersion: CANONICAL_SCOPE_ACK_VERSION,
    scopeAckHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    scopeAckTimestamp: '2026-10-09T01:40:00Z',
    stepCount: 0,
    findingCount: 0,
    createdAt: '2026-10-09T01:40:00Z',
    updatedAt: '2026-10-09T01:40:00Z'
  }

  beforeEach(() => {
    setActivePinia(createPinia())
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  function createWrapper(props = { visible: true }) {
    return mount(NewSessionModal, {
      props
    })
  }

  it('renders nothing when visible is false', () => {
    const wrapper = createWrapper({ visible: false })
    expect(wrapper.find('[role="dialog"]').exists()).toBe(false)
  })

  it('renders modal elements with default mode as PUBLIC and canonical statement text', () => {
    const wrapper = createWrapper()

    expect(wrapper.find('[role="dialog"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="target-url-input"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="mode-public-radio"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="mode-local-radio"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="scope-ack-checkbox"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="cancel-session-button"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="submit-session-button"]').exists()).toBe(true)

    // Verify default mode is PUBLIC
    const publicRadio = wrapper.find<HTMLInputElement>('[data-testid="mode-public-radio"]')
    expect(publicRadio.element.checked).toBe(true)

    // Verify verbatim statement and version badge
    expect(wrapper.text()).toContain(CANONICAL_SCOPE_ACK_STATEMENT)
    expect(wrapper.text()).toContain(`v${CANONICAL_SCOPE_ACK_VERSION}`)
    expect(wrapper.find('[data-testid="modal-error-callout"]').exists()).toBe(false)
  })

  it('disables submit button until both target URL is provided and scope is acknowledged', async () => {
    const wrapper = createWrapper()
    const submitBtn = wrapper.find('[data-testid="submit-session-button"]')

    // Initially disabled
    expect(submitBtn.attributes('disabled')).toBeDefined()

    // Fill target URL only -> still disabled
    await wrapper.find('[data-testid="target-url-input"]').setValue('https://example.com')
    expect(submitBtn.attributes('disabled')).toBeDefined()

    // Check scope ack checkbox -> enabled!
    await wrapper.find('[data-testid="scope-ack-checkbox"]').setValue(true)
    expect(submitBtn.attributes('disabled')).toBeUndefined()

    // Clear target URL -> disabled again
    await wrapper.find('[data-testid="target-url-input"]').setValue('   ')
    expect(submitBtn.attributes('disabled')).toBeDefined()

    // Restore target URL, uncheck scope -> disabled
    await wrapper.find('[data-testid="target-url-input"]').setValue('https://example.com')
    await wrapper.find('[data-testid="scope-ack-checkbox"]').setValue(false)
    expect(submitBtn.attributes('disabled')).toBeDefined()
  })

  it('submits valid session request with PUBLIC mode, emits created & update:visible events', async () => {
    const postSpy = vi.spyOn(http, 'post').mockResolvedValueOnce({
      data: mockCreatedSession,
      status: 201,
      statusText: 'Created',
      headers: {},
      config: {} as any
    })

    const wrapper = createWrapper()

    await wrapper.find('[data-testid="target-url-input"]').setValue('https://example.com')
    await wrapper.find('[data-testid="scope-ack-checkbox"]').setValue(true)

    await wrapper.find('form').trigger('submit.prevent')
    await flushPromises()

    expect(postSpy).toHaveBeenCalledTimes(1)
    expect(postSpy).toHaveBeenCalledWith('/sessions', {
      targetUrl: 'https://example.com',
      mode: 'PUBLIC',
      scopeAcknowledged: true,
      scopeAckVersion: '1.0.0'
    })

    expect(wrapper.emitted('created')).toBeTruthy()
    expect(wrapper.emitted('created')![0]).toEqual([mockCreatedSession])
    expect(wrapper.emitted('update:visible')).toBeTruthy()
    expect(wrapper.emitted('update:visible')![0]).toEqual([false])
  })

  it('submits valid session request with LOCAL mode when radio selected', async () => {
    const localSession: AuditSession = {
      ...mockCreatedSession,
      targetUrl: 'http://127.0.0.1:8080',
      mode: 'LOCAL'
    }

    const postSpy = vi.spyOn(http, 'post').mockResolvedValueOnce({
      data: localSession,
      status: 201,
      statusText: 'Created',
      headers: {},
      config: {} as any
    })

    const wrapper = createWrapper()

    await wrapper.find('[data-testid="target-url-input"]').setValue('http://127.0.0.1:8080')
    await wrapper.find('[data-testid="mode-local-radio"]').setValue()
    await wrapper.find('[data-testid="scope-ack-checkbox"]').setValue(true)

    await wrapper.find('form').trigger('submit.prevent')
    await flushPromises()

    expect(postSpy).toHaveBeenCalledWith('/sessions', {
      targetUrl: 'http://127.0.0.1:8080',
      mode: 'LOCAL',
      scopeAcknowledged: true,
      scopeAckVersion: '1.0.0'
    })
    expect(wrapper.emitted('created')![0]).toEqual([localSession])
  })

  it('renders RFC 9457 error callout with invalidParams on 403 PolicyEngine rejection', async () => {
    const policyProblem: ProblemDetail = {
      title: 'Scope Policy Violation',
      status: 403,
      detail: 'Target resolved to special-purpose IP (127.0.0.1) blocked in PUBLIC mode',
      invalidParams: [
        { name: 'targetUrl', reason: 'Loopback and private IPs are blocked in PUBLIC mode' }
      ]
    }

    vi.spyOn(http, 'post').mockRejectedValueOnce(new ApiError(policyProblem))

    const wrapper = createWrapper()

    await wrapper.find('[data-testid="target-url-input"]').setValue('http://127.0.0.1:8080')
    await wrapper.find('[data-testid="scope-ack-checkbox"]').setValue(true)

    await wrapper.find('form').trigger('submit.prevent')
    await flushPromises()

    const errorCallout = wrapper.find('[data-testid="modal-error-callout"]')
    expect(errorCallout.exists()).toBe(true)
    expect(errorCallout.text()).toContain('Scope Policy Violation')
    expect(errorCallout.text()).toContain('Target resolved to special-purpose IP (127.0.0.1) blocked in PUBLIC mode')

    const invalidParams = wrapper.findAll('[data-testid="invalid-param-item"]')
    expect(invalidParams.length).toBe(1)
    expect(invalidParams[0].text()).toContain('targetUrl')
    expect(invalidParams[0].text()).toContain('Loopback and private IPs are blocked in PUBLIC mode')

    // Modal must NOT have emitted created or closed
    expect(wrapper.emitted('created')).toBeFalsy()
  })

  it('disables controls and submit button while creating is true to prevent duplicate submission', async () => {
    const store = useSessionsStore()
    const wrapper = createWrapper()

    await wrapper.find('[data-testid="target-url-input"]').setValue('https://example.com')
    await wrapper.find('[data-testid="scope-ack-checkbox"]').setValue(true)

    // Simulate creation in flight
    store.creating = true
    await wrapper.vm.$nextTick()

    const submitBtn = wrapper.find('[data-testid="submit-session-button"]')
    expect(submitBtn.attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-testid="target-url-input"]').attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-testid="scope-ack-checkbox"]').attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-testid="cancel-session-button"]').attributes('disabled')).toBeDefined()
  })

  it('emits update:visible(false) and clears errors when Cancel button is clicked', async () => {
    const store = useSessionsStore()
    store.error = { title: 'Old Error', status: 400 }

    const wrapper = createWrapper()

    await wrapper.find('[data-testid="cancel-session-button"]').trigger('click')

    expect(wrapper.emitted('update:visible')).toBeTruthy()
    expect(wrapper.emitted('update:visible')![0]).toEqual([false])
    expect(store.error).toBeNull()
  })

  it('emits update:visible(false) and closes when Escape key is pressed on window', async () => {
    const wrapper = createWrapper({ visible: true })

    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await wrapper.vm.$nextTick()

    expect(wrapper.emitted('update:visible')).toBeTruthy()
    expect(wrapper.emitted('update:visible')![0]).toEqual([false])
  })

  it('does not emit update:visible on Escape key when creating is in flight', async () => {
    const store = useSessionsStore()
    store.creating = true
    const wrapper = createWrapper({ visible: true })

    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await wrapper.vm.$nextTick()

    expect(wrapper.emitted('update:visible')).toBeFalsy()
  })

  it('removes window keydown listener when component is unmounted', async () => {
    const removeSpy = vi.spyOn(window, 'removeEventListener')
    const wrapper = createWrapper({ visible: true })

    wrapper.unmount()

    expect(removeSpy).toHaveBeenCalledWith('keydown', expect.any(Function))
  })
})
