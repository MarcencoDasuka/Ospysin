<script setup lang="ts">
import { onMounted, onUnmounted, computed, ref, watch, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useSessionsStore } from '@/stores/sessions'
import { useWorkspaceStore } from '@/stores/workspace'
import { useHealthStore } from '@/stores/health'
import type { ToolMetadata, SseLogLevel, FindingSeverity } from '@/api/types'
import AppHeader from '@/components/AppHeader.vue'
import FindingsDrawer from '@/components/FindingsDrawer.vue'

const route = useRoute()
const router = useRouter()

const sessionsStore = useSessionsStore()
const { currentSession, loading: sessionLoading, error: sessionError } = storeToRefs(sessionsStore)

const workspaceStore = useWorkspaceStore()
const {
  toolsByTier,
  steps,
  activeStepId,
  activeStepDetail,
  sseEvents,
  sseConnectionState,
  policyAlertMessage,
  loadingTools,
  loadingSteps,
  loadingStepDetail,
  triggeringToolId,
  error: workspaceError,
  hasActiveExecution,
  latestCompletedHttpHeadersStepId,
  latestCompletedTechDetectStepId,
  latestAdvisory,
  chatMessages,
  requestingComment,
  sendingChat,
  findings,
  loadingFindings
} = storeToRefs(workspaceStore)

const healthStore = useHealthStore()
const { ollamaStatusText, isOllamaReady } = storeToRefs(healthStore)

const sessionId = computed(() => route.params.id as string)

// Findings Drawer state
const isFindingsDrawerOpen = ref(false)
const findingsDrawerRef = ref<InstanceType<typeof FindingsDrawer> | null>(null)

const activeFindingsCount = computed(() => {
  if (loadingFindings.value && findings.value.length === 0 && currentSession.value) {
    return currentSession.value.findingCount ?? 0
  }
  return Array.isArray(findings.value)
    ? findings.value.filter((f) => f.status !== 'REJECTED' && f.status !== 'FALSE_POSITIVE').length
    : 0
})

function handlePromoteObservation(obs: { id: string; category: string; description: string; severityHeuristic: string }) {
  isFindingsDrawerOpen.value = true
  findingsDrawerRef.value?.openNewFindingForm({
    observationId: obs.id,
    title: `[${obs.category}] ${obs.description.slice(0, 120)}`,
    description: obs.description,
    severity: obs.severityHeuristic as FindingSeverity,
    confidence: 'FIRM'
  })
}

function handleExportReport() {
  if (!currentSession.value) return
  router.push(`/sessions/${currentSession.value.id}/report`)
}

// View tabs & SSE display states
const activeViewTab = ref<'parsed' | 'raw'>('parsed')
const sseLevelFilter = ref<'ALL' | SseLogLevel>('ALL')
const autoScroll = ref(true)
const sseCollapsed = ref(false)
const eventListEl = ref<HTMLElement | null>(null)

// Tactical Chat & Advisory states
const chatInput = ref('')
const chatListEl = ref<HTMLElement | null>(null)

// Combined error for action banner
const combinedError = computed(() => sessionError.value || workspaceError.value)

const filteredSseEvents = computed(() => {
  if (sseLevelFilter.value === 'ALL') {
    return sseEvents.value
  }
  return sseEvents.value.filter((e) => e.level === sseLevelFilter.value)
})

// Auto-scroll handler
watch(
  () => sseEvents.value.length,
  async () => {
    if (autoScroll.value && eventListEl.value) {
      await nextTick()
      eventListEl.value.scrollTop = eventListEl.value.scrollHeight
    }
  }
)

// Chat auto-scroll handler
watch(
  () => chatMessages.value.length,
  async () => {
    if (chatListEl.value) {
      await nextTick()
      chatListEl.value.scrollTop = chatListEl.value.scrollHeight
    }
  }
)

async function handleRequestComment() {
  if (
    !currentSession.value ||
    currentSession.value.state !== 'ACTIVE' ||
    !activeStepDetail.value ||
    activeStepDetail.value.status !== 'COMPLETED' ||
    requestingComment.value
  ) {
    return
  }
  try {
    await workspaceStore.requestStepComment(currentSession.value.id, activeStepDetail.value.executionId)
  } catch {
    // Error captured in workspaceStore.error
  }
}

async function handleSendChat() {
  if (
    !currentSession.value ||
    currentSession.value.state !== 'ACTIVE' ||
    sendingChat.value ||
    !chatInput.value.trim()
  ) {
    return
  }
  const msg = chatInput.value.trim()
  chatInput.value = ''
  try {
    await workspaceStore.sendChatMessage(currentSession.value.id, msg)
  } catch {
    // Error captured in workspaceStore.error
  }
}

const toolOrderMap = computed<Map<string, string>>(() => {
  const map = new Map<string, string>()
  let index = 1
  for (const tierGroup of toolsByTier.value) {
    for (const tool of tierGroup.tools) {
      map.set(tool.id, String(index).padStart(2, '0'))
      index++
    }
  }
  return map
})

function getToolOrderNumber(toolId: string): string {
  return toolOrderMap.value.get(toolId) || '00'
}

let isUnmounted = false

async function loadWorkspaceData(id: string) {
  if (!id) return
  workspaceStore.resetWorkspace()
  try {
    await sessionsStore.fetchSessionById(id)
    if (isUnmounted || sessionId.value !== id) return
    await Promise.allSettled([
      workspaceStore.fetchTools(),
      workspaceStore.fetchSteps(id),
      workspaceStore.fetchFindings(id),
      healthStore.checkHealth()
    ])
    if (isUnmounted || sessionId.value !== id) return
    workspaceStore.connectSse(id)
  } catch {
    // Errors handled through store states
  }
}

watch(
  sessionId,
  async (newId, oldId) => {
    if (newId && newId !== oldId) {
      isFindingsDrawerOpen.value = false
      workspaceStore.resetWorkspace()
      await loadWorkspaceData(newId)
    }
  }
)

onMounted(async () => {
  isUnmounted = false
  if (sessionId.value) {
    await loadWorkspaceData(sessionId.value)
  }
})

onUnmounted(() => {
  isUnmounted = true
  workspaceStore.resetWorkspace()
})

async function handleComplete() {
  if (!currentSession.value || currentSession.value.state !== 'ACTIVE') return
  try {
    await sessionsStore.completeSession(currentSession.value.id)
  } catch {
    // Error captured in sessionsStore
  }
}

async function handleAbort() {
  if (!currentSession.value || currentSession.value.state !== 'ACTIVE') return
  try {
    await sessionsStore.abortSession(currentSession.value.id)
  } catch {
    // Error captured in sessionsStore
  }
}

function dismissActionError() {
  sessionsStore.clearError()
  workspaceStore.clearError()
}

function navigateBack() {
  router.push('/')
}

function isPrerequisiteMissing(tool: ToolMetadata): boolean {
  if (tool.id === 'security_headers_score') {
    const hasCompletedHttp =
      latestCompletedHttpHeadersStepId.value !== null ||
      (activeStepDetail.value?.toolId === 'http_headers' &&
        activeStepDetail.value.status === 'COMPLETED')
    return !hasCompletedHttp
  }
  if (tool.id === 'cve_matcher') {
    const hasCompletedTech =
      latestCompletedTechDetectStepId.value !== null ||
      (activeStepDetail.value?.toolId === 'tech_detect' &&
        activeStepDetail.value.status === 'COMPLETED')
    return !hasCompletedTech
  }
  return false
}

function getPrerequisiteHint(tool: ToolMetadata): string | null {
  if (tool.id === 'security_headers_score' && isPrerequisiteMissing(tool)) {
    return 'Requires completed http_headers step'
  }
  if (tool.id === 'cve_matcher' && isPrerequisiteMissing(tool)) {
    return 'Requires completed tech_detect step'
  }
  return null
}

function isToolDisabled(tool: ToolMetadata): boolean {
  if (!currentSession.value || currentSession.value.state !== 'ACTIVE') {
    return true
  }
  if (hasActiveExecution.value) {
    return true
  }
  if (triggeringToolId.value !== null) {
    return true
  }
  if (isPrerequisiteMissing(tool)) {
    return true
  }
  return false
}

function isToolActiveInQueue(toolId: string): boolean {
  return steps.value.some(
    (s) => s.toolId === toolId && (s.status === 'PENDING' || s.status === 'RUNNING')
  )
}

async function triggerToolRun(toolId: string) {
  if (!currentSession.value || isToolDisabled({ id: toolId } as ToolMetadata)) return
  try {
    await workspaceStore.runTool(currentSession.value.id, toolId)
  } catch {
    // Captured in workspaceStore.error
  }
}

async function handleStepSelect(stepId: string) {
  if (!currentSession.value) return
  await workspaceStore.selectStep(currentSession.value.id, stepId)
}

function formatTimestamp(isoString: string): string {
  try {
    const date = new Date(isoString)
    return date.toLocaleTimeString()
  } catch {
    return isoString
  }
}

// Helpers for parsed data viewing
function formatJson(data: Record<string, unknown> | null | undefined): string {
  if (!data) return '{}'
  try {
    return JSON.stringify(data, null, 2)
  } catch {
    return String(data)
  }
}

const parsedHeadersList = computed<[string, string][]>(() => {
  if (!activeStepDetail.value || activeStepDetail.value.toolId !== 'http_headers') {
    return []
  }
  const headers = activeStepDetail.value.parsedData?.headers
  if (headers && typeof headers === 'object') {
    return Object.entries(headers as Record<string, unknown>).map(([k, v]) => [k, String(v)])
  }
  return []
})

const parsedCookiesList = computed<Record<string, unknown>[]>(() => {
  if (!activeStepDetail.value || activeStepDetail.value.toolId !== 'http_headers') {
    return []
  }
  const cookies = activeStepDetail.value.parsedData?.cookies
  if (Array.isArray(cookies)) {
    return cookies as Record<string, unknown>[]
  }
  return []
})

const activeStepSummary = computed(() => {
  if (!activeStepId.value) return null
  return steps.value.find((s) => s.executionId === activeStepId.value) || null
})

const parsedRedirectChain = computed<string[]>(() => {
  if (!activeStepDetail.value || activeStepDetail.value.toolId !== 'http_headers') {
    return []
  }
  const chain = activeStepDetail.value.parsedData?.redirectChain
  if (!Array.isArray(chain)) {
    return []
  }
  return chain.map((item, idx) => {
    if (typeof item === 'string') {
      return item
    }
    if (item && typeof item === 'object') {
      const hopObj = item as Record<string, unknown>
      const hopNum = hopObj.hop ?? idx + 1
      const status = hopObj.statusCode ? ` (HTTP ${hopObj.statusCode})` : ''
      const from = hopObj.fromUrl ? String(hopObj.fromUrl) : ''
      const to = hopObj.toUrl ? String(hopObj.toUrl) : ''
      if (from || to) {
        return `Hop ${hopNum}${status}: ${from} -> ${to}`
      }
    }
    return String(item)
  })
})

const tlsSummary = computed(() => {
  if (!activeStepDetail.value || activeStepDetail.value.toolId !== 'tls_info') {
    return null
  }
  const d = activeStepDetail.value.parsedData || {}
  return {
    protocol: String(d.protocol || '-'),
    cipherSuite: String(d.cipherSuite || '-'),
    subject: String(d.subject || '-'),
    issuer: String(d.issuer || '-'),
    serialNumber: String(d.serialNumber || '-'),
    sigAlgName: String(d.sigAlgName || '-'),
    notBefore: String(d.notBefore || '-'),
    notAfter: String(d.notAfter || '-'),
    daysUntilExpiry: d.daysUntilExpiry != null ? String(d.daysUntilExpiry) : '-',
    selfSigned: Boolean(d.selfSigned),
    hostnameVerified: Boolean(d.hostnameVerified),
    trustVerified: Boolean(d.trustVerified),
    sanEntries: Array.isArray(d.sanEntries) ? (d.sanEntries as string[]) : []
  }
})
</script>

<template>
  <div class="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
    <!-- Top Platform Header -->
    <AppHeader />

    <!-- Loading State -->
    <div
      v-if="sessionLoading && !currentSession"
      class="flex-1 flex items-center justify-center p-8"
      data-testid="workspace-loading"
    >
      <div class="flex flex-col items-center gap-3 text-slate-400">
        <div class="h-8 w-8 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin"></div>
        <span class="text-xs font-mono">Loading audit session workspace...</span>
      </div>
    </div>

    <!-- Error State -->
    <div
      v-else-if="combinedError && !currentSession"
      class="flex-1 flex items-center justify-center p-8"
      data-testid="workspace-error-card"
    >
      <div class="w-full max-w-lg p-6 rounded-lg bg-rose-950/40 border border-rose-800/80 text-rose-200">
        <div class="flex items-start gap-3">
          <i class="pi pi-exclamation-triangle text-rose-400 text-xl mt-0.5"></i>
          <div class="flex-1">
            <h3 class="font-bold text-sm text-rose-200">
              {{ combinedError.title || 'Failed to Load Session' }}
            </h3>
            <p class="text-xs text-rose-300 mt-1 leading-relaxed">
              {{ combinedError.detail || 'The requested audit session could not be retrieved.' }}
            </p>
            <div class="mt-4">
              <button
                type="button"
                data-testid="back-to-sessions-button"
                @click="navigateBack"
                class="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors"
              >
                &larr; Back to Sessions
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Session Workspace Content -->
    <main v-else-if="currentSession" class="flex-1 flex flex-col overflow-hidden">
      <!-- Session Context Bar -->
      <div class="bg-slate-900 border-b border-slate-800 px-6 py-2.5 flex items-center justify-between gap-4">
        <div class="flex items-center gap-3 min-w-0">
          <button
            type="button"
            data-testid="back-to-sessions-button"
            @click="navigateBack"
            class="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1 font-mono hover:underline shrink-0"
          >
            <span>&larr;</span>
            <span>Sessions</span>
          </button>
          <span class="text-slate-700 font-mono">|</span>

          <!-- Target URL -->
          <div class="flex items-center gap-2 truncate">
            <span class="text-xs text-slate-400 font-mono shrink-0">Target:</span>
            <span
              data-testid="workspace-target-url"
              class="text-sm font-bold font-mono text-cyan-400 truncate"
            >
              {{ currentSession.targetUrl }}
            </span>
          </div>

          <!-- Mode Badge -->
          <span
            data-testid="workspace-mode-badge"
            :class="[
              'text-[10px] px-2 py-0.5 rounded font-mono font-semibold uppercase tracking-wider border shrink-0',
              currentSession.mode === 'LOCAL'
                ? 'bg-amber-950/80 text-amber-300 border-amber-600/50'
                : 'bg-cyan-950/80 text-cyan-300 border-cyan-600/50'
            ]"
          >
            {{ currentSession.mode }}
          </span>

          <!-- State Badge -->
          <span
            data-testid="workspace-state-badge"
            :class="[
              'text-[10px] px-2 py-0.5 rounded font-mono font-semibold uppercase tracking-wider border shrink-0',
              currentSession.state === 'ACTIVE'
                ? 'bg-emerald-950/80 text-emerald-300 border-emerald-600/50'
                : currentSession.state === 'COMPLETED'
                  ? 'bg-slate-800 text-slate-300 border-slate-700'
                  : 'bg-rose-950/80 text-rose-300 border-rose-600/50'
            ]"
          >
            {{ currentSession.state }}
          </span>
        </div>

        <!-- Action Controls -->
        <div class="flex items-center gap-2 shrink-0">
          <button
            type="button"
            data-testid="toggle-findings-drawer-button"
            @click="isFindingsDrawerOpen = !isFindingsDrawerOpen"
            class="px-3 py-1 rounded bg-slate-800 hover:bg-cyan-950 active:bg-cyan-900 text-slate-200 hover:text-cyan-300 text-xs font-mono font-medium border border-slate-700 hover:border-cyan-700/60 transition-colors flex items-center gap-1.5"
          >
            <i class="pi pi-shield text-xs text-cyan-400"></i>
            <span>Findings ({{ activeFindingsCount }})</span>
          </button>
          <button
            type="button"
            data-testid="open-report-view-button"
            @click="handleExportReport"
            class="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 active:bg-slate-600 text-slate-200 text-xs font-mono font-medium border border-slate-700 hover:border-slate-600 transition-colors flex items-center gap-1.5"
          >
            <i class="pi pi-file text-xs"></i>
            <span>Export Report</span>
          </button>
          <button
            type="button"
            data-testid="complete-session-button"
            :disabled="currentSession.state !== 'ACTIVE' || sessionLoading || hasActiveExecution"
            @click="handleComplete"
            class="px-3 py-1 rounded bg-slate-800 hover:bg-emerald-900/60 active:bg-emerald-800 text-slate-200 hover:text-emerald-300 text-xs font-medium border border-slate-700 hover:border-emerald-600/50 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Complete Session
          </button>
          <button
            type="button"
            data-testid="abort-session-button"
            :disabled="currentSession.state !== 'ACTIVE' || sessionLoading"
            @click="handleAbort"
            class="px-3 py-1 rounded bg-slate-800 hover:bg-rose-900/60 active:bg-rose-800 text-slate-200 hover:text-rose-300 text-xs font-medium border border-slate-700 hover:border-rose-600/50 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Abort Session
          </button>
        </div>
      </div>

      <!-- Policy Alert Banner -->
      <div
        v-if="policyAlertMessage"
        data-testid="policy-alert-banner"
        class="bg-amber-950/90 border-b border-amber-800/80 px-6 py-2 flex items-center justify-between gap-3 text-xs text-amber-200"
        role="alert"
      >
        <div class="flex items-center gap-2 min-w-0">
          <i class="pi pi-shield text-amber-400 text-sm shrink-0"></i>
          <span class="font-bold text-amber-100">Policy Alert:</span>
          <span class="truncate text-amber-200">{{ policyAlertMessage }}</span>
        </div>
        <button
          type="button"
          @click="workspaceStore.dismissPolicyAlert()"
          class="text-amber-400 hover:text-amber-100 text-xs font-mono p-1 rounded hover:bg-amber-900/50 transition-colors shrink-0"
        >
          [Dismiss]
        </button>
      </div>

      <!-- Action Error Banner -->
      <div
        v-if="combinedError"
        data-testid="workspace-action-error"
        class="bg-rose-950/80 border-b border-rose-800/80 px-6 py-2.5 flex items-center justify-between gap-3 text-xs text-rose-200"
        role="alert"
      >
        <div class="flex items-center gap-2 min-w-0">
          <i class="pi pi-exclamation-circle text-rose-400 text-sm shrink-0"></i>
          <div class="truncate">
            <strong class="font-bold text-rose-100">{{ combinedError.title || 'Action Error' }}:</strong>
            <span class="ml-1 text-rose-200">{{ combinedError.detail || 'An error occurred during session action.' }}</span>
          </div>
        </div>
        <button
          type="button"
          data-testid="dismiss-action-error-button"
          @click="dismissActionError"
          class="text-rose-400 hover:text-rose-100 text-xs font-mono p-1 rounded hover:bg-rose-900/50 transition-colors shrink-0"
          title="Dismiss error"
        >
          [Dismiss]
        </button>
      </div>

      <!-- 4-Panel Workspace Grid Container -->
      <div class="flex-1 p-4 grid grid-cols-12 gap-4 overflow-y-auto">
        <!-- 1. Left Panel: Categorized 15-Tool Catalog (3 cols) -->
        <section
          class="col-span-12 lg:col-span-3 bg-slate-900 border border-slate-800 rounded-lg p-3 flex flex-col min-h-[500px] lg:h-[calc(100vh-14rem)] lg:max-h-[780px] overflow-hidden"
        >
          <div class="flex items-center justify-between pb-2 border-b border-slate-800">
            <h3 class="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
              Tool Catalog (15)
            </h3>
            <span
              v-if="loadingTools"
              class="text-[10px] text-cyan-400 font-mono flex items-center gap-1"
            >
              <div class="h-2 w-2 border border-cyan-400 border-t-transparent rounded-full animate-spin"></div>
              Loading...
            </span>
          </div>

          <div class="flex-1 overflow-y-auto mt-2 space-y-4 pr-1">
            <div v-for="tierGroup in toolsByTier" :key="tierGroup.tier" class="space-y-2">
              <h4 class="text-[11px] font-semibold text-slate-400 uppercase font-mono tracking-wider flex items-center gap-1.5">
                <span class="w-1.5 h-1.5 rounded-full bg-cyan-500"></span>
                <span>{{ tierGroup.label }}</span>
                <span class="text-slate-600">({{ tierGroup.tools.length }})</span>
              </h4>

              <div class="space-y-1.5">
                <div
                  v-for="tool in tierGroup.tools"
                  :key="tool.id"
                  :data-testid="'tool-card-' + tool.id"
                  class="p-2.5 rounded border border-slate-800/80 bg-slate-950/60 hover:border-slate-700/80 transition-colors flex flex-col gap-1.5"
                >
                  <div class="flex items-center justify-between gap-1">
                    <div class="flex items-center gap-1.5 min-w-0">
                      <span
                        :data-testid="'tool-order-badge-' + tool.id"
                        class="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/60 shrink-0"
                      >
                        #{{ getToolOrderNumber(tool.id) }}
                      </span>
                      <span class="text-xs font-semibold text-slate-200 truncate">{{ tool.name }}</span>
                    </div>
                    <span class="text-[9px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 shrink-0">
                      {{ tool.category }}
                    </span>
                  </div>

                  <p class="text-[10px] text-slate-400 line-clamp-2 leading-relaxed">
                    {{ tool.description }}
                  </p>

                  <div class="mt-1 flex items-center justify-between gap-2 pt-1 border-t border-slate-900">
                    <span
                      v-if="getPrerequisiteHint(tool)"
                      class="text-[9px] text-amber-400 font-mono leading-tight truncate"
                      :title="getPrerequisiteHint(tool)!"
                    >
                      {{ getPrerequisiteHint(tool) }}
                    </span>
                    <span v-else class="text-[9px] font-mono text-slate-600 truncate">{{ tool.id }}</span>

                    <button
                      type="button"
                      :data-testid="'run-tool-' + tool.id"
                      :disabled="isToolDisabled(tool)"
                      @click="triggerToolRun(tool.id)"
                      :class="[
                        'px-2.5 py-1 rounded text-[11px] font-medium font-mono border transition-all shrink-0 flex items-center gap-1',
                        isToolDisabled(tool)
                          ? 'bg-slate-800/40 text-slate-500 border-slate-800 cursor-not-allowed opacity-50'
                          : 'bg-cyan-950/60 hover:bg-cyan-900 text-cyan-300 border-cyan-700/60 hover:border-cyan-500'
                      ]"
                    >
                      <span
                        v-if="triggeringToolId === tool.id || isToolActiveInQueue(tool.id)"
                        class="h-2 w-2 border border-cyan-300 border-t-transparent rounded-full animate-spin"
                      ></span>
                      <span>Run</span>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <!-- 2. Center Panel: Results & Execution History (6 cols) -->
        <section
          class="col-span-12 lg:col-span-6 bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col min-h-[500px] lg:h-[calc(100vh-14rem)] lg:max-h-[780px] overflow-hidden"
        >
          <!-- Center Panel Header: Step Timeline -->
          <div class="flex items-center justify-between pb-2 border-b border-slate-800">
            <h3 class="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
              Results & Execution History
            </h3>
            <span v-if="loadingSteps" class="text-[10px] text-cyan-400 font-mono">Refreshing steps...</span>
          </div>

          <!-- Step Timeline Tabs -->
          <div
            v-if="steps.length > 0"
            data-testid="step-timeline"
            class="flex flex-wrap items-center gap-1.5 max-h-32 overflow-y-auto py-2 border-b border-slate-800/80 mb-3 shrink-0"
          >
            <button
              v-for="(step, idx) in steps"
              :key="step.executionId"
              type="button"
              :data-testid="'step-tab-' + step.executionId"
              @click="handleStepSelect(step.executionId)"
              :class="[
                'px-2.5 py-1 rounded text-xs font-mono border transition-colors shrink-0 flex items-center gap-1.5',
                activeStepId === step.executionId
                  ? 'bg-cyan-950/80 border-cyan-500 text-cyan-200 shadow-sm'
                  : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
              ]"
            >
              <span class="text-slate-500">#{{ idx + 1 }}</span>
              <span class="font-semibold">{{ step.toolId }}</span>
              <span
                :class="[
                  'text-[9px] px-1 py-0.2 rounded font-semibold uppercase',
                  step.status === 'COMPLETED'
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/60'
                    : step.status === 'RUNNING'
                      ? 'bg-amber-950 text-amber-400 border border-amber-800/60 animate-pulse'
                      : step.status === 'FAILED'
                        ? 'bg-rose-950 text-rose-400 border border-rose-800/60'
                        : 'bg-slate-800 text-slate-400'
                ]"
              >
                {{ step.status }}
              </span>
              <span v-if="step.durationMs != null" class="text-[9px] text-slate-500">
                {{ step.durationMs }}ms
              </span>
              <span
                v-if="step.observationCount > 0"
                :data-testid="'step-observations-count-' + step.executionId"
                class="px-1 text-[9px] rounded-full bg-cyan-900/60 text-cyan-300 font-bold"
              >
                {{ step.observationCount }}
              </span>
            </button>
          </div>

          <!-- Dual-View Tabs Bar -->
          <div
            v-if="steps.length > 0 && activeStepDetail"
            class="flex items-center justify-between pb-2 mb-3 border-b border-slate-800"
          >
            <div class="flex items-center gap-1 bg-slate-950 p-0.5 rounded border border-slate-800">
              <button
                type="button"
                data-testid="tab-parsed-view"
                @click="activeViewTab = 'parsed'"
                :class="[
                  'px-3 py-1 rounded text-xs font-mono font-medium transition-colors',
                  activeViewTab === 'parsed'
                    ? 'bg-slate-800 text-cyan-300 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                ]"
              >
                Parsed View
              </button>
              <button
                type="button"
                data-testid="tab-raw-output"
                @click="activeViewTab = 'raw'"
                :class="[
                  'px-3 py-1 rounded text-xs font-mono font-medium transition-colors',
                  activeViewTab === 'raw'
                    ? 'bg-slate-800 text-cyan-300 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                ]"
              >
                Raw Output
              </button>
            </div>

            <div class="flex items-center gap-2">
              <span
                v-if="activeStepDetail.observations && activeStepDetail.observations.length > 0"
                class="text-xs font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800/60 text-cyan-300 font-semibold"
              >
                {{ activeStepDetail.observations.length }} Observations
              </span>
              <span
                v-if="activeStepDetail.durationMs != null"
                class="text-xs font-mono text-slate-400"
              >
                Duration: {{ activeStepDetail.durationMs }}ms
              </span>
            </div>
          </div>

          <!-- Inspector Content Body -->
          <div class="flex-1 overflow-y-auto">
            <!-- 1. Empty State (No Steps Yet) -->
            <div
              v-if="steps.length === 0"
              data-testid="inspector-empty-state"
              class="h-full flex flex-col items-center justify-center p-8 text-center text-slate-500 space-y-2"
            >
              <i class="pi pi-compass text-3xl text-slate-600 mb-1"></i>
              <p class="text-sm font-medium text-slate-400">No tools executed yet</p>
              <p class="text-xs text-slate-500 max-w-sm">
                Select an inspection tool from the catalog on the left to begin probing the target.
              </p>
            </div>

            <!-- 2. Loading / Running Step State -->
            <div
              v-else-if="
                loadingStepDetail ||
                activeStepSummary?.status === 'PENDING' ||
                activeStepSummary?.status === 'RUNNING' ||
                activeStepDetail?.status === 'PENDING' ||
                activeStepDetail?.status === 'RUNNING'
              "
              data-testid="inspector-step-running"
              class="h-full flex flex-col items-center justify-center p-8 text-center space-y-3"
            >
              <div class="h-8 w-8 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin"></div>
              <p class="text-xs font-mono text-slate-300">
                Executing probe {{ activeStepDetail?.toolId || activeStepSummary?.toolId || 'step' }}...
              </p>
              <span class="text-[10px] font-mono text-slate-500">
                Network sockets and policy checks running in background queue.
              </span>
            </div>

            <!-- 3. Failed / Cancelled State -->
            <div
              v-else-if="
                activeStepDetail &&
                (activeStepDetail.status === 'FAILED' || activeStepDetail.status === 'CANCELLED')
              "
              data-testid="inspector-step-failed"
              class="p-4 rounded bg-rose-950/30 border border-rose-900/60 text-rose-200 space-y-2"
            >
              <div class="flex items-center gap-2">
                <i class="pi pi-times-circle text-rose-400 text-sm"></i>
                <h4 class="font-mono text-xs font-bold uppercase tracking-wider text-rose-300">
                  Tool Execution {{ activeStepDetail.status }}
                </h4>
              </div>
              <p class="text-xs font-mono text-rose-200">
                {{ activeStepDetail.failureReason || 'An execution error occurred.' }}
              </p>
            </div>

            <!-- 4. Parsed View Content -->
            <div
              v-else-if="activeStepDetail && activeViewTab === 'parsed'"
              data-testid="parsed-view-content"
              class="space-y-4"
            >
              <!-- A. Specialized http_headers Inspector -->
              <div
                v-if="activeStepDetail.toolId === 'http_headers'"
                class="space-y-4"
              >
                <!-- Summary bar -->
                <div class="p-3 bg-slate-950 rounded border border-slate-800 flex flex-wrap items-center justify-between gap-3 font-mono text-xs">
                  <div class="flex items-center gap-2">
                    <span class="text-slate-400">Status:</span>
                    <span class="font-bold text-emerald-400">
                      {{ activeStepDetail.parsedData?.statusCode }}
                    </span>
                    <span class="text-slate-500">({{ activeStepDetail.parsedData?.httpVersion }})</span>
                  </div>
                  <div class="flex items-center gap-2 truncate">
                    <span class="text-slate-400">Final URL:</span>
                    <span class="text-cyan-400 truncate">{{ activeStepDetail.parsedData?.finalUrl }}</span>
                  </div>
                  <div v-if="activeStepDetail.parsedData?.serverBanner" class="flex items-center gap-1.5">
                    <span class="text-slate-400">Server:</span>
                    <span class="text-amber-300 font-semibold">{{ activeStepDetail.parsedData?.serverBanner }}</span>
                  </div>
                </div>

                <!-- Redirect Chain (if present) -->
                <div
                  v-if="parsedRedirectChain.length > 0"
                  data-testid="http-redirect-chain"
                  class="p-2.5 bg-slate-950 rounded border border-slate-800 space-y-1 font-mono text-xs"
                >
                  <div class="text-[10px] uppercase font-bold text-slate-400">Redirect Chain</div>
                  <div v-for="(hop, hIdx) in parsedRedirectChain" :key="hIdx" class="text-slate-300 text-[11px] truncate">
                    &rarr; {{ hop }}
                  </div>
                </div>

                <!-- Response Headers Table -->
                <div class="space-y-1.5">
                  <h4 class="text-xs font-mono font-bold uppercase text-slate-300 tracking-wider">
                    Response Headers ({{ parsedHeadersList.length }})
                  </h4>
                  <div class="overflow-x-auto rounded border border-slate-800 bg-slate-950">
                    <table
                      data-testid="http-headers-table"
                      class="w-full text-left font-mono text-xs border-collapse"
                    >
                      <thead>
                        <tr class="bg-slate-900 border-b border-slate-800 text-slate-400 text-[11px]">
                          <th class="py-1.5 px-3 font-semibold w-1/3">Header Name</th>
                          <th class="py-1.5 px-3 font-semibold">Value</th>
                        </tr>
                      </thead>
                      <tbody class="divide-y divide-slate-900">
                        <tr
                          v-for="[key, val] in parsedHeadersList"
                          :key="key"
                          class="hover:bg-slate-900/40 transition-colors"
                        >
                          <td class="py-1.5 px-3 text-cyan-300 font-medium align-top">{{ key }}</td>
                          <td class="py-1.5 px-3 text-slate-300 break-all">{{ val }}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>

                <!-- Cookies Table -->
                <div class="space-y-1.5">
                  <h4 class="text-xs font-mono font-bold uppercase text-slate-300 tracking-wider">
                    Parsed Set-Cookie Directives ({{ parsedCookiesList.length }})
                  </h4>
                  <div v-if="parsedCookiesList.length > 0" class="overflow-x-auto rounded border border-slate-800 bg-slate-950">
                    <table
                      data-testid="http-cookies-table"
                      class="w-full text-left font-mono text-xs border-collapse"
                    >
                      <thead>
                        <tr class="bg-slate-900 border-b border-slate-800 text-slate-400 text-[10px] uppercase">
                          <th class="py-1.5 px-3">Name</th>
                          <th class="py-1.5 px-2">Secure</th>
                          <th class="py-1.5 px-2">HttpOnly</th>
                          <th class="py-1.5 px-2">SameSite</th>
                          <th class="py-1.5 px-2">Path</th>
                          <th class="py-1.5 px-2">Domain</th>
                        </tr>
                      </thead>
                      <tbody class="divide-y divide-slate-900">
                        <tr
                          v-for="(c, cIdx) in parsedCookiesList"
                          :key="cIdx"
                          class="hover:bg-slate-900/40 transition-colors"
                        >
                          <td class="py-1.5 px-3 text-cyan-300 font-semibold">{{ c.name }}</td>
                          <td class="py-1.5 px-2">
                            <span :class="c.secure ? 'text-emerald-400 font-bold' : 'text-rose-400'">
                              {{ c.secure ? 'Yes' : 'No' }}
                            </span>
                          </td>
                          <td class="py-1.5 px-2">
                            <span :class="c.httpOnly ? 'text-emerald-400 font-bold' : 'text-rose-400'">
                              {{ c.httpOnly ? 'Yes' : 'No' }}
                            </span>
                          </td>
                          <td class="py-1.5 px-2 text-slate-300">{{ c.sameSite || '-' }}</td>
                          <td class="py-1.5 px-2 text-slate-300">{{ c.path || '-' }}</td>
                          <td class="py-1.5 px-2 text-slate-300">{{ c.domain || '-' }}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                  <div v-else class="p-3 bg-slate-950 rounded border border-slate-800 text-xs text-slate-500 font-mono">
                    No Set-Cookie directives detected in response.
                  </div>
                </div>
              </div>

              <!-- B. Specialized tls_info Inspector -->
              <div
                v-else-if="activeStepDetail.toolId === 'tls_info' && tlsSummary"
                data-testid="tls-info-summary"
                class="space-y-4"
              >
                <!-- Handshake Summary -->
                <div class="p-3 bg-slate-950 rounded border border-slate-800 grid grid-cols-2 gap-3 font-mono text-xs">
                  <div>
                    <span class="text-slate-500 block text-[10px] uppercase font-bold">Protocol</span>
                    <span class="text-cyan-300 font-bold text-sm">{{ tlsSummary.protocol }}</span>
                  </div>
                  <div>
                    <span class="text-slate-500 block text-[10px] uppercase font-bold">Cipher Suite</span>
                    <span class="text-slate-200 text-xs break-all">{{ tlsSummary.cipherSuite }}</span>
                  </div>
                  <div>
                    <span class="text-slate-500 block text-[10px] uppercase font-bold">Days Until Expiry</span>
                    <span
                      :class="[
                        'font-bold text-sm',
                        Number(tlsSummary.daysUntilExpiry) > 30 ? 'text-emerald-400' : 'text-rose-400'
                      ]"
                    >
                      {{ tlsSummary.daysUntilExpiry }} days
                    </span>
                  </div>
                  <div>
                    <span class="text-slate-500 block text-[10px] uppercase font-bold">Signature Algorithm</span>
                    <span class="text-slate-200">{{ tlsSummary.sigAlgName }}</span>
                  </div>
                </div>

                <!-- Verification Badges -->
                <div class="flex flex-wrap gap-2 font-mono text-xs">
                  <span
                    :class="[
                      'px-2.5 py-1 rounded border font-semibold',
                      tlsSummary.trustVerified
                        ? 'bg-emerald-950/60 border-emerald-800 text-emerald-300'
                        : 'bg-rose-950/60 border-rose-800 text-rose-300'
                    ]"
                  >
                    CA Trust: {{ tlsSummary.trustVerified ? 'Verified' : 'Untrusted / Incomplete Chain' }}
                  </span>
                  <span
                    :class="[
                      'px-2.5 py-1 rounded border font-semibold',
                      tlsSummary.hostnameVerified
                        ? 'bg-emerald-950/60 border-emerald-800 text-emerald-300'
                        : 'bg-rose-950/60 border-rose-800 text-rose-300'
                    ]"
                  >
                    Hostname: {{ tlsSummary.hostnameVerified ? 'RFC 9525 Verified' : 'Mismatch' }}
                  </span>
                  <span
                    v-if="tlsSummary.selfSigned"
                    class="px-2.5 py-1 rounded border bg-amber-950/60 border-amber-800 text-amber-300 font-semibold"
                  >
                    Self-Signed Certificate
                  </span>
                </div>

                <!-- Certificate Identities -->
                <div class="p-3 bg-slate-950 rounded border border-slate-800 space-y-2 font-mono text-xs">
                  <div>
                    <span class="text-slate-500 block text-[10px] uppercase font-bold">Subject</span>
                    <span class="text-slate-200 break-all">{{ tlsSummary.subject }}</span>
                  </div>
                  <div>
                    <span class="text-slate-500 block text-[10px] uppercase font-bold">Issuer</span>
                    <span class="text-slate-300 break-all">{{ tlsSummary.issuer }}</span>
                  </div>
                  <div class="grid grid-cols-2 gap-2 pt-1 border-t border-slate-900">
                    <div>
                      <span class="text-slate-500 block text-[10px] uppercase font-bold">Valid From</span>
                      <span class="text-slate-400 text-[11px]">{{ tlsSummary.notBefore }}</span>
                    </div>
                    <div>
                      <span class="text-slate-500 block text-[10px] uppercase font-bold">Valid Until</span>
                      <span class="text-slate-400 text-[11px]">{{ tlsSummary.notAfter }}</span>
                    </div>
                  </div>
                  <div>
                    <span class="text-slate-500 block text-[10px] uppercase font-bold">Serial Number</span>
                    <span class="text-slate-400 text-[11px] break-all">{{ tlsSummary.serialNumber }}</span>
                  </div>
                </div>

                <!-- SAN Entries -->
                <div v-if="tlsSummary.sanEntries.length > 0" class="space-y-1.5">
                  <h4 class="text-xs font-mono font-bold uppercase text-slate-300 tracking-wider">
                    Subject Alternative Names (SANs)
                  </h4>
                  <div class="flex flex-wrap gap-1.5">
                    <span
                      v-for="san in tlsSummary.sanEntries"
                      :key="san"
                      class="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-xs"
                    >
                      {{ san }}
                    </span>
                  </div>
                </div>
              </div>

              <!-- C. Generic Structured Data Inspector (All other tools) -->
              <div v-else data-testid="generic-parsed-data" class="space-y-3">
                <div
                  v-if="activeStepDetail.score != null"
                  class="p-3 bg-slate-950 rounded border border-slate-800 flex items-center justify-between font-mono"
                >
                  <span class="text-xs text-slate-400 font-semibold uppercase">Security Score</span>
                  <span
                    :class="[
                      'text-lg font-bold px-3 py-1 rounded border',
                      activeStepDetail.score >= 80
                        ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
                        : activeStepDetail.score >= 50
                          ? 'bg-amber-950 text-amber-300 border-amber-700'
                          : 'bg-rose-950 text-rose-300 border-rose-700'
                    ]"
                  >
                    {{ activeStepDetail.score }} / 100
                  </span>
                </div>

                <div class="p-3 bg-slate-950 rounded border border-slate-800 space-y-2">
                  <h4 class="text-xs font-mono font-bold uppercase text-slate-400">Structured Payload</h4>
                  <pre class="font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap">{{
                    formatJson(activeStepDetail.parsedData)
                  }}</pre>
                </div>
              </div>

              <!-- Automated Observations List -->
              <div
                v-if="activeStepDetail.observations && activeStepDetail.observations.length > 0"
                data-testid="step-observations-list"
                class="space-y-2 pt-2 border-t border-slate-800"
              >
                <h4 class="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <i class="pi pi-bolt text-amber-400"></i>
                  <span>Automated Observations ({{ activeStepDetail.observations.length }})</span>
                </h4>

                <div class="space-y-1.5">
                  <div
                    v-for="obs in activeStepDetail.observations"
                    :key="obs.id"
                    class="p-2.5 rounded bg-slate-950 border border-slate-800/80 flex items-start gap-2.5"
                  >
                    <span
                      :class="[
                        'text-[9px] px-2 py-0.5 rounded font-mono font-bold uppercase tracking-wider shrink-0 border mt-0.5',
                        obs.severityHeuristic === 'HIGH'
                          ? 'bg-rose-950 text-rose-300 border-rose-800/80'
                          : obs.severityHeuristic === 'MEDIUM'
                            ? 'bg-amber-950 text-amber-300 border-amber-800/80'
                            : obs.severityHeuristic === 'LOW'
                              ? 'bg-sky-950 text-sky-300 border-sky-800/80'
                              : 'bg-slate-800 text-slate-300 border-slate-700'
                      ]"
                    >
                      {{ obs.severityHeuristic }}
                    </span>
                    <div class="flex-1 min-w-0">
                      <div class="flex items-center justify-between gap-2">
                        <span class="text-xs font-semibold text-slate-200">{{ obs.description }}</span>
                        <span class="text-[9px] font-mono text-slate-500 shrink-0">{{ obs.category }}</span>
                      </div>
                      <div class="mt-2 flex justify-end">
                        <button
                          type="button"
                          :data-testid="'promote-observation-' + obs.id"
                          :disabled="currentSession?.state === 'ABORTED'"
                          @click="handlePromoteObservation(obs)"
                          class="px-2 py-0.5 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-[10px] font-mono font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1"
                        >
                          <i class="pi pi-arrow-up-right text-[9px]"></i>
                          <span>Promote to Finding</span>
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- 5. Raw Output View Content -->
            <div
              v-else-if="activeStepDetail && activeViewTab === 'raw'"
              data-testid="raw-output-content"
              class="h-full flex flex-col"
            >
              <pre
                class="font-mono text-xs text-slate-300 bg-slate-950 p-4 rounded border border-slate-800 overflow-auto whitespace-pre-wrap flex-1 leading-relaxed"
              >{{ activeStepDetail.rawOutput || 'No raw output captured.' }}</pre>
            </div>
          </div>
        </section>

        <!-- 3. Right Panel: AI Advisor (3 cols) -->
        <section
          data-testid="advisor-panel"
          class="col-span-12 lg:col-span-3 bg-slate-900 border border-slate-800 rounded-lg p-3 flex flex-col min-h-[500px] lg:h-[calc(100vh-14rem)] lg:max-h-[780px] overflow-hidden"
        >
          <!-- Advisor Header -->
          <div class="flex items-center justify-between pb-2 border-b border-slate-800 shrink-0">
            <div class="flex items-center gap-1.5">
              <i class="pi pi-microchip-ai text-cyan-400 text-sm"></i>
              <h3 class="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
                AI Advisor
              </h3>
            </div>
            <span
              :class="[
                'text-[10px] font-mono px-2 py-0.5 rounded border',
                isOllamaReady
                  ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700'
                  : 'bg-slate-800 text-slate-400 border-slate-700'
              ]"
            >
              {{ ollamaStatusText }}
            </span>
          </div>

          <!-- Advisor Body Container -->
          <div class="flex-1 min-h-0 flex flex-col gap-3 pt-3 overflow-hidden">
            <!-- Top Section: Commentary & Suggested Tool (Scrollable if needed) -->
            <div class="shrink-0 space-y-3 overflow-y-auto max-h-[42%] pr-1">
              <!-- Latest Commentary Card -->
              <div
                data-testid="advisor-comment-card"
                class="p-3 rounded bg-slate-950/80 border border-slate-800 space-y-2"
              >
                <div class="flex items-center justify-between gap-2">
                  <span class="text-[11px] font-bold uppercase font-mono text-slate-300 tracking-wider">
                    Latest Commentary
                  </span>
                  <button
                    type="button"
                    data-testid="refresh-comment-button"
                    :disabled="!activeStepDetail || activeStepDetail.status !== 'COMPLETED' || currentSession.state !== 'ACTIVE' || requestingComment"
                    @click="handleRequestComment"
                    class="px-2 py-0.5 rounded text-[10px] font-mono border transition-colors flex items-center gap-1 bg-slate-900 text-cyan-300 border-cyan-800/60 hover:border-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed"
                    title="Request on-demand analysis for current step"
                  >
                    <span v-if="requestingComment" class="h-2 w-2 border border-cyan-300 border-t-transparent rounded-full animate-spin"></span>
                    <span>{{ requestingComment ? 'Analyzing...' : (latestAdvisory ? 'Re-analyze' : 'Analyze Step') }}</span>
                  </button>
                </div>

                <div v-if="requestingComment" class="flex items-center gap-2 py-2 text-xs font-mono text-cyan-400">
                  <div class="h-3 w-3 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin"></div>
                  <span>Advisor generating step analysis...</span>
                </div>
                <p
                  v-else-if="latestAdvisory && latestAdvisory.comment"
                  class="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap font-sans"
                >{{ latestAdvisory.comment }}</p>
                <p v-else class="text-xs text-slate-500 italic">
                  Select a completed step and click 'Analyze Step' or run a tool to receive AI tactical guidance.
                </p>
              </div>

              <!-- Suggested Next Step Card -->
              <div
                v-if="latestAdvisory && latestAdvisory.suggestedTool"
                data-testid="suggested-tool-card"
                class="p-3 rounded bg-cyan-950/30 border border-cyan-800/60 space-y-2"
              >
                <div class="flex items-center justify-between gap-1">
                  <span class="text-[11px] font-bold uppercase font-mono text-cyan-300 tracking-wider flex items-center gap-1">
                    <i class="pi pi-compass text-cyan-400"></i>
                    <span>Suggested Next Step</span>
                  </span>
                  <span class="text-[9px] font-mono px-1.5 py-0.5 rounded bg-cyan-900/60 text-cyan-200">
                    {{ latestAdvisory.suggestedTool }}
                  </span>
                </div>

                <p v-if="latestAdvisory.suggestedReason" class="text-xs text-slate-300 leading-relaxed">
                  {{ latestAdvisory.suggestedReason }}
                </p>

                <div class="pt-1">
                  <button
                    type="button"
                    data-testid="run-suggested-tool-button"
                    :disabled="currentSession.state !== 'ACTIVE' || hasActiveExecution || isToolDisabled({ id: latestAdvisory.suggestedTool } as ToolMetadata)"
                    @click="triggerToolRun(latestAdvisory.suggestedTool!)"
                    class="w-full px-3 py-1.5 rounded text-xs font-semibold font-mono border bg-cyan-900/70 hover:bg-cyan-800 text-cyan-200 border-cyan-600 transition-colors disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-1.5"
                  >
                    <span>Run {{ latestAdvisory.suggestedTool }}</span>
                  </button>
                </div>
              </div>
            </div>

            <!-- Bottom Section: Tactical Chat (Flex-1) -->
            <div class="flex-1 min-h-0 flex flex-col rounded bg-slate-950/60 border border-slate-800 p-2.5 overflow-hidden">
              <div class="flex items-center justify-between pb-1.5 mb-1.5 border-b border-slate-800/80 shrink-0">
                <span class="text-[11px] font-bold uppercase font-mono text-slate-300 tracking-wider flex items-center gap-1">
                  <i class="pi pi-comments text-slate-400"></i>
                  <span>Tactical Chat</span>
                </span>
                <span v-if="sendingChat" class="text-[10px] font-mono text-cyan-400 flex items-center gap-1">
                  <span class="h-2 w-2 border border-cyan-400 border-t-transparent rounded-full animate-spin"></span>
                  Reasoning...
                </span>
              </div>

              <!-- Chat Messages List -->
              <div
                ref="chatListEl"
                data-testid="advisor-chat-list"
                class="flex-1 min-h-0 overflow-y-auto space-y-2 pr-1 font-mono text-xs"
              >
                <div
                  v-if="chatMessages.length === 0"
                  class="h-full flex items-center justify-center text-center p-3 text-slate-500 text-[11px]"
                >
                  No messages yet. Ask tactical self-defense questions about discovered findings.
                </div>

                <div
                  v-for="msg in chatMessages"
                  :key="msg.id"
                  data-testid="advisor-chat-message"
                  :class="[
                    'p-2 rounded text-xs leading-relaxed space-y-1',
                    msg.role === 'user'
                      ? 'bg-slate-900 border border-slate-800 text-slate-200'
                      : 'bg-cyan-950/40 border border-cyan-900/60 text-slate-200'
                  ]"
                >
                  <div class="flex items-center justify-between text-[10px]">
                    <span :class="msg.role === 'user' ? 'text-cyan-400 font-bold' : 'text-emerald-400 font-bold'">
                      {{ msg.role === 'user' ? '[Operator]' : '[Advisor]' }}
                    </span>
                    <span class="text-slate-500">{{ formatTimestamp(msg.timestamp) }}</span>
                  </div>
                  <div class="whitespace-pre-wrap font-sans text-slate-300">{{ msg.content }}</div>
                </div>

                <div v-if="sendingChat" class="p-2 rounded bg-cyan-950/20 border border-cyan-900/40 flex items-center gap-2 text-cyan-400 text-xs">
                  <div class="h-2.5 w-2.5 border border-cyan-400 border-t-transparent rounded-full animate-spin"></div>
                  <span>Advisor is evaluating session telemetry...</span>
                </div>
              </div>

              <!-- Chat Input Form -->
              <form
                @submit.prevent="handleSendChat"
                class="mt-2 pt-2 border-t border-slate-800 flex items-center gap-1.5 shrink-0"
              >
                <input
                  v-model="chatInput"
                  data-testid="advisor-chat-input"
                  type="text"
                  placeholder="Ask tactical question..."
                  :disabled="currentSession.state !== 'ACTIVE' || sendingChat"
                  class="flex-1 bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed font-sans"
                />
                <button
                  type="submit"
                  data-testid="advisor-chat-submit"
                  :disabled="currentSession.state !== 'ACTIVE' || sendingChat || !chatInput.trim()"
                  class="px-2.5 py-1 rounded bg-cyan-950 text-cyan-300 border border-cyan-700/60 hover:bg-cyan-900 text-xs font-mono font-medium disabled:opacity-40 disabled:cursor-not-allowed transition-colors shrink-0"
                >
                  Send
                </button>
              </form>
            </div>
          </div>
        </section>

        <!-- 4. Bottom Panel: Live Event Stream (SSE) (12 cols) -->
        <section
          class="col-span-12 bg-slate-900 border border-slate-800 rounded-lg p-3 flex flex-col transition-all"
        >
          <div class="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-slate-800">
            <div class="flex items-center gap-3">
              <h3 class="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
                Live Event Stream (SSE)
              </h3>
              <span class="text-xs font-mono text-slate-500">
                ({{ sseEvents.length }} events)
              </span>

              <!-- Connection Status Badge -->
              <span
                data-testid="sse-status-badge"
                :class="[
                  'text-[10px] font-mono px-2 py-0.5 rounded font-semibold uppercase tracking-wider border',
                  sseConnectionState === 'CONNECTED'
                    ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
                    : sseConnectionState === 'CONNECTING'
                      ? 'bg-amber-950 text-amber-300 border-amber-700 animate-pulse'
                      : sseConnectionState === 'ERROR'
                        ? 'bg-rose-950 text-rose-300 border-rose-700'
                        : 'bg-slate-800 text-slate-400 border-slate-700'
                ]"
              >
                {{ sseConnectionState }}
              </span>
            </div>

            <!-- Controls: Filter, Autoscroll, Clear, Collapse -->
            <div class="flex items-center gap-2 font-mono text-xs">
              <!-- Level Filter -->
              <div class="flex items-center gap-1">
                <span class="text-[11px] text-slate-500">Filter:</span>
                <select
                  data-testid="sse-level-filter"
                  v-model="sseLevelFilter"
                  class="bg-slate-950 border border-slate-800 text-slate-300 text-[11px] rounded px-2 py-0.5 focus:outline-none focus:border-cyan-500"
                >
                  <option value="ALL">ALL</option>
                  <option value="INFO">INFO</option>
                  <option value="SUCCESS">SUCCESS</option>
                  <option value="WARN">WARN</option>
                  <option value="ERROR">ERROR</option>
                </select>
              </div>

              <!-- Auto-scroll Toggle -->
              <button
                type="button"
                data-testid="sse-autoscroll-toggle"
                @click="autoScroll = !autoScroll"
                :class="[
                  'px-2 py-0.5 rounded text-[11px] border transition-colors',
                  autoScroll
                    ? 'bg-cyan-950/80 text-cyan-300 border-cyan-700'
                    : 'bg-slate-950 text-slate-500 border-slate-800'
                ]"
                title="Toggle autoscroll lock"
              >
                Auto-scroll: {{ autoScroll ? 'ON' : 'OFF' }}
              </button>

              <!-- Clear Log Button -->
              <button
                type="button"
                data-testid="sse-clear-button"
                @click="workspaceStore.clearSseEvents()"
                class="px-2 py-0.5 rounded text-[11px] bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800 hover:border-slate-700 transition-colors"
              >
                Clear
              </button>

              <!-- Collapse Toggle Button -->
              <button
                type="button"
                data-testid="sse-collapse-toggle"
                @click="sseCollapsed = !sseCollapsed"
                class="px-2 py-0.5 rounded text-[11px] bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800 hover:border-slate-700 transition-colors"
              >
                {{ sseCollapsed ? 'Expand' : 'Collapse' }}
              </button>
            </div>
          </div>

          <!-- Monospace Scrollable Event Stream List -->
          <div
            v-if="!sseCollapsed"
            ref="eventListEl"
            data-testid="sse-event-list"
            class="mt-2 max-h-40 overflow-y-auto space-y-1 font-mono text-xs pr-1"
          >
            <div
              v-for="ev in filteredSseEvents"
              :key="ev.id"
              data-testid="sse-event-item"
              class="flex items-start gap-2 py-0.5 hover:bg-slate-950/40 rounded px-1"
            >
              <span class="text-slate-500 text-[10px] shrink-0">
                {{ formatTimestamp(ev.timestamp) }}
              </span>
              <span
                :class="[
                  'text-[9px] px-1 py-0.2 rounded font-bold uppercase shrink-0',
                  ev.level === 'SUCCESS'
                    ? 'bg-emerald-950 text-emerald-400'
                    : ev.level === 'WARN'
                      ? 'bg-amber-950 text-amber-400'
                      : ev.level === 'ERROR'
                        ? 'bg-rose-950 text-rose-400'
                        : 'bg-slate-800 text-slate-300'
                ]"
              >
                [{{ ev.level }}]
              </span>
              <span class="text-slate-400 text-[10px] shrink-0 font-semibold">
                [{{ ev.eventName }}]
              </span>
              <span class="text-slate-200 break-all">{{ ev.message }}</span>
            </div>

            <div
              v-if="filteredSseEvents.length === 0"
              class="py-4 text-center text-slate-600 text-xs font-mono"
            >
              No events captured.
            </div>
          </div>
        </section>
      </div>
    </main>

    <!-- Findings Curation Drawer -->
    <FindingsDrawer
      :is-open="isFindingsDrawerOpen"
      @close="isFindingsDrawerOpen = false"
      ref="findingsDrawerRef"
    />
  </div>
</template>
