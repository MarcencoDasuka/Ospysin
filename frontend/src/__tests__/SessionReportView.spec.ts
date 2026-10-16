import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { setActivePinia, createPinia } from 'pinia'
import { createRouter, createMemoryHistory } from 'vue-router'
import SessionReportView from '@/views/SessionReportView.vue'
import { http } from '@/api/http'
import type { AuditSession } from '@/api/types'

describe('Screen 4: Standalone Report View (SessionReportView.vue)', () => {
  let router: ReturnType<typeof createRouter>

  const mockSession: AuditSession = {
    id: 'test-session-123',
    targetUrl: 'https://example.com/target',
    mode: 'PUBLIC',
    state: 'COMPLETED',
    scopeAcknowledged: true,
    scopeAckVersion: '1.0.0',
    scopeAckHash: 'hash-xyz',
    scopeAckTimestamp: '2026-10-09T01:40:00Z',
    stepCount: 3,
    findingCount: 2,
    createdAt: '2026-10-09T01:40:00Z',
    updatedAt: '2026-10-09T01:50:00Z'
  }

  const sampleReportHtml = '<!DOCTYPE html><html><head><title>Report</title></head><body><h1>Security Audit Report</h1></body></html>'

  beforeEach(() => {
    setActivePinia(createPinia())

    router = createRouter({
      history: createMemoryHistory(),
      routes: [
        {
          path: '/sessions/:id/report',
          name: 'session-report',
          component: SessionReportView
        },
        {
          path: '/sessions/:id',
          name: 'session-workspace',
          component: { template: '<div>Workspace</div>' }
        }
      ]
    })

    vi.spyOn(http, 'get').mockImplementation(async (url: string) => {
      if (url.includes('/sessions/test-session-123/report')) {
        return { data: sampleReportHtml, status: 200 } as any
      }
      if (url.includes('/sessions/test-session-123')) {
        return { data: mockSession, status: 200 } as any
      }
      throw new Error('Not found: ' + url)
    })
  })

  async function createWrapper(sessionId = 'test-session-123') {
    await router.push(`/sessions/${sessionId}/report`)
    await router.isReady()

    const wrapper = mount(SessionReportView, {
      global: {
        plugins: [router]
      }
    })

    await flushPromises()
    return wrapper
  }

  it('renders standalone report view with sandboxed iframe containing report HTML', async () => {
    const wrapper = await createWrapper()

    const iframe = wrapper.find('[data-testid="report-preview-iframe"]')
    expect(iframe.exists()).toBe(true)
    expect(iframe.attributes('srcdoc')).toBe(sampleReportHtml)
    expect(iframe.attributes('sandbox')).toBe('')
    expect(wrapper.text()).toContain('https://example.com/target')
  })

  it('back-to-workspace-button navigates back to session workspace', async () => {
    const wrapper = await createWrapper()

    const backBtn = wrapper.find('[data-testid="back-to-workspace-button"]')
    expect(backBtn.exists()).toBe(true)

    await backBtn.trigger('click')
    await flushPromises()

    expect(router.currentRoute.value.path).toBe('/sessions/test-session-123')
  })

  it('print-report-button invokes window.print()', async () => {
    const printSpy = vi.spyOn(window, 'print').mockImplementation(() => {})

    const wrapper = await createWrapper()
    const printBtn = wrapper.find('[data-testid="print-report-button"]')
    expect(printBtn.exists()).toBe(true)

    await printBtn.trigger('click')
    expect(printSpy).toHaveBeenCalled()
  })

  it('download-html-report-button triggers file download using Blob URL', async () => {
    const createObjectURLSpy = vi.fn().mockReturnValue('blob:http://localhost/test-blob')
    const revokeObjectURLSpy = vi.fn()
    globalThis.URL.createObjectURL = createObjectURLSpy
    globalThis.URL.revokeObjectURL = revokeObjectURLSpy

    const wrapper = await createWrapper()
    const downloadBtn = wrapper.find('[data-testid="download-html-report-button"]')
    expect(downloadBtn.exists()).toBe(true)

    await downloadBtn.trigger('click')

    expect(createObjectURLSpy).toHaveBeenCalled()
    expect(revokeObjectURLSpy).toHaveBeenCalledWith('blob:http://localhost/test-blob')
  })
})
