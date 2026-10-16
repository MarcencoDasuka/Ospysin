<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useSessionsStore } from '@/stores/sessions'
import { useWorkspaceStore } from '@/stores/workspace'
import AppHeader from '@/components/AppHeader.vue'

const route = useRoute()
const router = useRouter()

const sessionsStore = useSessionsStore()
const { currentSession, loading: sessionLoading, error: sessionError } = storeToRefs(sessionsStore)

const workspaceStore = useWorkspaceStore()
const { error: workspaceError } = storeToRefs(workspaceStore)

const sessionId = computed(() => route.params.id as string)

const reportHtml = ref('')
const loadingReport = ref(false)

const combinedError = computed(() => sessionError.value || workspaceError.value)

onMounted(async () => {
  if (sessionId.value) {
    loadingReport.value = true
    try {
      await sessionsStore.fetchSessionById(sessionId.value)
      reportHtml.value = await workspaceStore.fetchReportHtml(sessionId.value)
    } catch {
      // Errors captured in stores
    } finally {
      loadingReport.value = false
    }
  }
})

function handleBackToWorkspace() {
  router.push(`/sessions/${sessionId.value}`)
}

function handleDownloadHtml() {
  if (!reportHtml.value) return
  const blob = new Blob([reportHtml.value], { type: 'text/html;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `ospysin-report-${sessionId.value}.html`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

function handlePrint() {
  window.print()
}
</script>

<template>
  <div class="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
    <AppHeader class="print:hidden" />

    <!-- Top Action Bar -->
    <div
      class="print:hidden bg-slate-900 border-b border-slate-800 px-6 py-3 flex flex-wrap items-center justify-between gap-4"
    >
      <div class="flex items-center gap-3">
        <button
          type="button"
          data-testid="back-to-workspace-button"
          @click="handleBackToWorkspace"
          class="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono border border-slate-700 transition-colors"
        >
          <i class="pi pi-arrow-left text-xs"></i>
          <span>Workspace</span>
        </button>

        <span class="text-slate-700 font-mono">|</span>

        <div v-if="currentSession" class="flex items-center gap-2 truncate">
          <span class="text-xs text-slate-400 font-mono">Target:</span>
          <span class="text-sm font-bold font-mono text-cyan-400 truncate">{{ currentSession.targetUrl }}</span>
        </div>
      </div>

      <div class="flex items-center gap-2">
        <button
          type="button"
          data-testid="download-html-report-button"
          :disabled="loadingReport || !reportHtml"
          @click="handleDownloadHtml"
          class="px-3 py-1.5 rounded bg-slate-800 hover:bg-cyan-900/60 text-slate-200 hover:text-cyan-300 text-xs font-mono font-medium border border-slate-700 hover:border-cyan-600/50 transition-colors disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1.5"
        >
          <i class="pi pi-download text-xs"></i>
          <span>Download HTML</span>
        </button>

        <button
          type="button"
          data-testid="print-report-button"
          :disabled="loadingReport || !reportHtml"
          @click="handlePrint"
          class="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-mono font-semibold transition-colors disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1.5"
        >
          <i class="pi pi-print text-xs"></i>
          <span>Print / Save PDF</span>
        </button>
      </div>
    </div>

    <!-- Error Banner -->
    <div
      v-if="combinedError"
      data-testid="report-error-banner"
      class="print:hidden m-6 p-4 rounded bg-rose-950/60 border border-rose-800 text-rose-200 text-xs font-mono space-y-1"
    >
      <div class="font-bold flex items-center gap-2">
        <i class="pi pi-exclamation-triangle"></i>
        <span>{{ combinedError.title || 'Error Loading Report' }}</span>
      </div>
      <div>{{ combinedError.detail || 'Unable to retrieve standalone security report.' }}</div>
    </div>

    <!-- Loading State -->
    <div
      v-if="loadingReport || (sessionLoading && !currentSession)"
      data-testid="report-loading-state"
      class="flex-1 flex items-center justify-center p-12"
    >
      <div class="flex flex-col items-center gap-3 text-slate-400">
        <div class="h-8 w-8 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin"></div>
        <span class="text-xs font-mono">Generating standalone security audit report...</span>
      </div>
    </div>

    <!-- Report Preview Container -->
    <main v-else class="flex-1 p-6 flex flex-col">
      <iframe
        data-testid="report-preview-iframe"
        :srcdoc="reportHtml"
        sandbox=""
        class="w-full flex-1 min-h-[750px] bg-white rounded border border-slate-800 shadow-xl"
        title="Audit Session Security Report"
      ></iframe>
    </main>
  </div>
</template>
