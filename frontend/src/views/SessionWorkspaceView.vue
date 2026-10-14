<script setup lang="ts">
import { onMounted, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useSessionsStore } from '@/stores/sessions'
import AppHeader from '@/components/AppHeader.vue'

const route = useRoute()
const router = useRouter()
const sessionsStore = useSessionsStore()
const { currentSession, loading, error } = storeToRefs(sessionsStore)

const sessionId = computed(() => route.params.id as string)

watch(
  sessionId,
  async (newId) => {
    if (newId) {
      try {
        await sessionsStore.fetchSessionById(newId)
      } catch {
        // Error handled via sessionsStore.error
      }
    }
  }
)

onMounted(async () => {
  if (sessionId.value) {
    try {
      await sessionsStore.fetchSessionById(sessionId.value)
    } catch {
      // Error handled via sessionsStore.error
    }
  }
})

async function handleComplete() {
  if (!currentSession.value || currentSession.value.state !== 'ACTIVE') return
  try {
    await sessionsStore.completeSession(currentSession.value.id)
  } catch {
    // Error captured in store
  }
}

async function handleAbort() {
  if (!currentSession.value || currentSession.value.state !== 'ACTIVE') return
  try {
    await sessionsStore.abortSession(currentSession.value.id)
  } catch {
    // Error captured in store
  }
}

function navigateBack() {
  router.push('/')
}
</script>

<template>
  <div class="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
    <!-- Top Platform Header -->
    <AppHeader />

    <!-- Loading State -->
    <div
      v-if="loading && !currentSession"
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
      v-else-if="error && !currentSession"
      class="flex-1 flex items-center justify-center p-8"
      data-testid="workspace-error-card"
    >
      <div class="w-full max-w-lg p-6 rounded-lg bg-rose-950/40 border border-rose-800/80 text-rose-200">
        <div class="flex items-start gap-3">
          <i class="pi pi-exclamation-triangle text-rose-400 text-xl mt-0.5"></i>
          <div class="flex-1">
            <h3 class="font-bold text-sm text-rose-200">
              {{ error.title || 'Failed to Load Session' }}
            </h3>
            <p class="text-xs text-rose-300 mt-1 leading-relaxed">
              {{ error.detail || 'The requested audit session could not be retrieved.' }}
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
            data-testid="complete-session-button"
            :disabled="currentSession.state !== 'ACTIVE' || loading"
            @click="handleComplete"
            class="px-3 py-1 rounded bg-slate-800 hover:bg-emerald-900/60 active:bg-emerald-800 text-slate-200 hover:text-emerald-300 text-xs font-medium border border-slate-700 hover:border-emerald-600/50 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Complete Session
          </button>
          <button
            type="button"
            data-testid="abort-session-button"
            :disabled="currentSession.state !== 'ACTIVE' || loading"
            @click="handleAbort"
            class="px-3 py-1 rounded bg-slate-800 hover:bg-rose-900/60 active:bg-rose-800 text-slate-200 hover:text-rose-300 text-xs font-medium border border-slate-700 hover:border-rose-600/50 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Abort Session
          </button>
        </div>
      </div>

      <!-- Action Error Banner (e.g. 409 Conflict during complete/abort) -->
      <div
        v-if="error"
        data-testid="workspace-action-error"
        class="bg-rose-950/80 border-b border-rose-800/80 px-6 py-2.5 flex items-center justify-between gap-3 text-xs text-rose-200"
        role="alert"
      >
        <div class="flex items-center gap-2 min-w-0">
          <i class="pi pi-exclamation-circle text-rose-400 text-sm shrink-0"></i>
          <div class="truncate">
            <strong class="font-bold text-rose-100">{{ error.title || 'Action Error' }}:</strong>
            <span class="ml-1 text-rose-200">{{ error.detail || 'An error occurred during session action.' }}</span>
          </div>
        </div>
        <button
          type="button"
          data-testid="dismiss-action-error-button"
          @click="sessionsStore.clearError()"
          class="text-rose-400 hover:text-rose-100 text-xs font-mono p-1 rounded hover:bg-rose-900/50 transition-colors shrink-0"
          title="Dismiss error"
        >
          [Dismiss]
        </button>
      </div>

      <!-- 4-Panel Workspace Shell Container (Phase 11 Implementation Placeholder) -->
      <div class="flex-1 p-6 grid grid-cols-12 gap-4 overflow-hidden">
        <!-- Left Panel: Tool Catalog (3 cols) -->
        <section class="col-span-12 lg:col-span-3 bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col">
          <div class="flex items-center justify-between pb-2 border-b border-slate-800">
            <h3 class="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
              Tool Catalog (15)
            </h3>
            <span class="text-[10px] text-slate-500 font-mono">Phase 9</span>
          </div>
          <div class="flex-1 flex items-center justify-center p-6 text-center text-xs text-slate-500">
            Tool catalog registry and queue dispatch will be active in Phase 9 & 10.
          </div>
        </section>

        <!-- Center Panel: Results & History (6 cols) -->
        <section class="col-span-12 lg:col-span-6 bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col">
          <div class="flex items-center justify-between pb-2 border-b border-slate-800">
            <h3 class="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
              Results & Execution History
            </h3>
            <span class="text-[10px] text-slate-500 font-mono">Phase 11</span>
          </div>
          <div class="flex-1 flex items-center justify-center p-6 text-center text-xs text-slate-500">
            Inspection step results and finding drawer will be connected in Phase 11.
          </div>
        </section>

        <!-- Right Panel: AI Advisor (3 cols) -->
        <section class="col-span-12 lg:col-span-3 bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col">
          <div class="flex items-center justify-between pb-2 border-b border-slate-800">
            <h3 class="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
              AI Advisor (Ollama)
            </h3>
            <span class="text-[10px] text-slate-500 font-mono">Phase 12</span>
          </div>
          <div class="flex-1 flex items-center justify-center p-6 text-center text-xs text-slate-500">
            Dolphin3-Cyber local LLM advisory and chat interface will be active in Phase 12.
          </div>
        </section>

        <!-- Bottom Panel: Live Event Stream (12 cols) -->
        <section class="col-span-12 bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col max-h-40">
          <div class="flex items-center justify-between pb-2 border-b border-slate-800">
            <h3 class="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
              Live Event Stream (SSE)
            </h3>
            <span class="text-[10px] text-slate-500 font-mono">Phase 9 Hub</span>
          </div>
          <div class="flex-1 flex items-center justify-center p-3 text-center text-xs text-slate-500 font-mono">
            SSE connection hub will attach in Phase 9.
          </div>
        </section>
      </div>
    </main>
  </div>
</template>
