<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useSessionsStore } from '@/stores/sessions'
import type { AuditSession } from '@/api/types'
import AppHeader from '@/components/AppHeader.vue'
import NewSessionModal from '@/components/NewSessionModal.vue'

const router = useRouter()
const sessionsStore = useSessionsStore()

const { sessions, page, size, totalElements, totalPages, loading, error } =
  storeToRefs(sessionsStore)

const isNewModalOpen = ref(false)

onMounted(async () => {
  try {
    await sessionsStore.fetchSessions(0, 20)
  } catch {
    // Error captured in sessionsStore.error
  }
})

function openNewSessionModal() {
  isNewModalOpen.value = true
}

function handleSessionCreated(session: AuditSession) {
  isNewModalOpen.value = false
  router.push(`/sessions/${session.id}`)
}

function openSession(sessionId: string) {
  router.push(`/sessions/${sessionId}`)
}

async function handlePrevPage() {
  if (page.value > 0 && !loading.value) {
    try {
      await sessionsStore.fetchSessions(page.value - 1, size.value)
    } catch {
      // Error captured in sessionsStore.error
    }
  }
}

async function handleNextPage() {
  if (page.value < totalPages.value - 1 && !loading.value) {
    try {
      await sessionsStore.fetchSessions(page.value + 1, size.value)
    } catch {
      // Error captured in sessionsStore.error
    }
  }
}

function formatTimestamp(isoString: string): string {
  try {
    const d = new Date(isoString)
    if (isNaN(d.getTime())) return isoString
    return d.toISOString().replace('T', ' ').slice(0, 16)
  } catch {
    return isoString
  }
}
</script>

<template>
  <div class="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
    <!-- Screen 1 Header -->
    <AppHeader />

    <!-- Main Content: Session List View (Screen 1) -->
    <main class="flex-1 p-6 max-w-7xl w-full mx-auto flex flex-col">
      <!-- Section Title & Actions -->
      <div class="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h2 class="text-xl font-bold tracking-tight text-slate-100">Audit Sessions</h2>
          <p class="text-xs text-slate-400 mt-0.5">
            Manage target authorizations, active investigations, and security audit sessions.
          </p>
        </div>
        <div>
          <button
            type="button"
            data-testid="new-session-button"
            @click="openNewSessionModal"
            class="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 text-white font-medium text-xs tracking-wide shadow-sm border border-cyan-500/30 transition-colors flex items-center gap-1.5 cursor-pointer"
          >
            <i class="pi pi-plus text-xs"></i>
            <span>+ New Audit Session</span>
          </button>
        </div>
      </div>

      <!-- Error alert if list loading failed -->
      <div
        v-if="error && !isNewModalOpen"
        data-testid="sessions-list-error"
        class="mt-4 p-4 rounded-md bg-rose-950/60 border border-rose-800 text-rose-200 text-xs"
        role="alert"
      >
        <span class="font-bold">{{ error.title || 'Error' }}:</span> {{ error.detail || 'Failed to load sessions' }}
      </div>

      <!-- Sessions Table Shell -->
      <div class="mt-6 bg-slate-900 border border-slate-800 rounded-lg overflow-hidden shadow-lg flex-1 flex flex-col">
        <div class="overflow-x-auto flex-1">
          <table data-testid="sessions-table" class="w-full text-left text-xs font-mono">
            <thead class="bg-slate-800/80 text-slate-300 border-b border-slate-700/80 uppercase tracking-wider">
              <tr>
                <th class="px-4 py-3 font-semibold">Target URL</th>
                <th class="px-4 py-3 font-semibold">Mode</th>
                <th class="px-4 py-3 font-semibold">State</th>
                <th class="px-4 py-3 font-semibold text-center">Steps</th>
                <th class="px-4 py-3 font-semibold text-center">Findings</th>
                <th class="px-4 py-3 font-semibold">Created At</th>
                <th class="px-4 py-3 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800 text-slate-300">
              <!-- Loading Skeleton / Spinner -->
              <tr v-if="loading && sessions.length === 0" data-testid="sessions-loading">
                <td colspan="7" class="px-4 py-12 text-center text-slate-400 font-sans">
                  <div class="flex flex-col items-center justify-center gap-2">
                    <div class="h-8 w-8 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin"></div>
                    <span class="text-xs font-mono">Loading audit sessions...</span>
                  </div>
                </td>
              </tr>

              <!-- Empty State -->
              <tr v-else-if="sessions.length === 0" data-testid="empty-sessions-state">
                <td colspan="7" class="px-4 py-12 text-center text-slate-500 font-sans">
                  <div class="flex flex-col items-center justify-center gap-2">
                    <div class="h-10 w-10 rounded-full bg-slate-800 flex items-center justify-center text-slate-400">
                      <i class="pi pi-shield text-lg"></i>
                    </div>
                    <span class="text-sm font-medium text-slate-300">No active audit sessions found</span>
                    <span class="text-xs text-slate-500 max-w-sm">
                      Initialize a target scope to begin non-destructive reconnaissance, vulnerability inspection, and automated LLM advisory.
                    </span>
                  </div>
                </td>
              </tr>

              <!-- Session Rows -->
              <tr
                v-for="session in sessions"
                :key="session.id"
                data-testid="session-row"
                class="hover:bg-slate-800/40 transition-colors"
              >
                <!-- Target URL -->
                <td class="px-4 py-3 font-bold text-slate-100 max-w-xs truncate" data-testid="session-target-url">
                  {{ session.targetUrl }}
                </td>

                <!-- Mode -->
                <td class="px-4 py-3">
                  <span
                    data-testid="session-mode-badge"
                    :class="[
                      'text-[10px] px-2 py-0.5 rounded font-mono font-semibold uppercase tracking-wider border',
                      session.mode === 'LOCAL'
                        ? 'bg-amber-950/70 text-amber-300 border-amber-600/40'
                        : 'bg-cyan-950/70 text-cyan-300 border-cyan-600/40'
                    ]"
                  >
                    {{ session.mode }}
                  </span>
                </td>

                <!-- State -->
                <td class="px-4 py-3">
                  <span
                    data-testid="session-state-badge"
                    :class="[
                      'text-[10px] px-2 py-0.5 rounded font-mono font-semibold uppercase tracking-wider border',
                      session.state === 'ACTIVE'
                        ? 'bg-emerald-950/70 text-emerald-300 border-emerald-600/40'
                        : session.state === 'COMPLETED'
                          ? 'bg-slate-800 text-slate-300 border-slate-700'
                          : 'bg-rose-950/70 text-rose-300 border-rose-600/40'
                    ]"
                  >
                    {{ session.state }}
                  </span>
                </td>

                <!-- Steps -->
                <td class="px-4 py-3 text-center font-mono text-slate-300" data-testid="session-steps-count">
                  {{ session.stepCount }}
                </td>

                <!-- Findings -->
                <td class="px-4 py-3 text-center font-mono text-slate-300" data-testid="session-findings-count">
                  {{ session.findingCount }}
                </td>

                <!-- Created At -->
                <td class="px-4 py-3 text-slate-400 font-mono text-[11px]" data-testid="session-created-at">
                  {{ formatTimestamp(session.createdAt) }}
                </td>

                <!-- Actions -->
                <td class="px-4 py-3 text-right">
                  <button
                    type="button"
                    data-testid="open-session-button"
                    @click="openSession(session.id)"
                    class="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-900/60 active:bg-cyan-800 text-slate-200 hover:text-cyan-300 text-xs font-medium border border-slate-700 hover:border-cyan-600/40 transition-colors cursor-pointer"
                  >
                    [Open]
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Pagination Bar -->
        <div
          v-if="totalPages > 1"
          data-testid="pagination-controls"
          class="px-4 py-3 border-t border-slate-800 bg-slate-900/80 flex items-center justify-between text-xs font-mono text-slate-400"
        >
          <div>
            Showing {{ sessions.length }} of {{ totalElements }} sessions
          </div>
          <div class="flex items-center gap-3">
            <button
              type="button"
              data-testid="prev-page-button"
              :disabled="page === 0 || loading"
              @click="handlePrevPage"
              class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              &larr; Previous
            </button>
            <span data-testid="page-indicator" class="text-slate-300 font-semibold">
              Page {{ page + 1 }} of {{ totalPages }}
            </span>
            <button
              type="button"
              data-testid="next-page-button"
              :disabled="page >= totalPages - 1 || loading"
              @click="handleNextPage"
              class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              Next &rarr;
            </button>
          </div>
        </div>
      </div>
    </main>

    <!-- Screen 2: New Session Setup Modal -->
    <NewSessionModal
      v-model:visible="isNewModalOpen"
      @created="handleSessionCreated"
    />
  </div>
</template>
