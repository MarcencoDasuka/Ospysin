<script setup lang="ts">
import { ref, watch, computed, onUnmounted } from 'vue'
import { storeToRefs } from 'pinia'
import { useSessionsStore } from '@/stores/sessions'
import {
  type SessionMode,
  type AuditSession,
  CANONICAL_SCOPE_ACK_VERSION,
  CANONICAL_SCOPE_ACK_STATEMENT
} from '@/api/types'

const props = defineProps<{
  visible: boolean
}>()

const emit = defineEmits<{
  (e: 'update:visible', value: boolean): void
  (e: 'created', session: AuditSession): void
}>()

const sessionsStore = useSessionsStore()
const { creating, error } = storeToRefs(sessionsStore)

const targetUrl = ref('')
const mode = ref<SessionMode>('PUBLIC')
const scopeAcknowledged = ref(false)

const canSubmit = computed(() => {
  return targetUrl.value.trim().length > 0 && scopeAcknowledged.value && !creating.value
})

function closeModal() {
  if (creating.value) return
  emit('update:visible', false)
  sessionsStore.clearError()
}

function handleKeydown(event: KeyboardEvent) {
  if (event.key === 'Escape' && props.visible && !creating.value) {
    closeModal()
  }
}

watch(
  () => props.visible,
  (isOpen) => {
    if (isOpen) {
      sessionsStore.clearError()
      targetUrl.value = ''
      mode.value = 'PUBLIC'
      scopeAcknowledged.value = false
      window.addEventListener('keydown', handleKeydown)
    } else {
      window.removeEventListener('keydown', handleKeydown)
    }
  },
  { immediate: true }
)

onUnmounted(() => {
  window.removeEventListener('keydown', handleKeydown)
})

async function handleSubmit() {
  if (!canSubmit.value) {
    return
  }

  try {
    const session = await sessionsStore.createSession({
      targetUrl: targetUrl.value.trim(),
      mode: mode.value,
      scopeAcknowledged: scopeAcknowledged.value,
      scopeAckVersion: CANONICAL_SCOPE_ACK_VERSION
    })

    emit('created', session)
    emit('update:visible', false)
  } catch {
    // Error is captured in sessionsStore.error and displayed in modal-error-callout
  }
}
</script>

<template>
  <div
    v-if="visible"
    class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm"
    role="dialog"
    aria-modal="true"
    aria-labelledby="modal-title"
    @click.self="closeModal"
  >
    <div
      class="w-full max-w-xl bg-slate-900 border border-slate-800 rounded-lg shadow-2xl overflow-hidden flex flex-col"
    >
      <!-- Modal Header -->
      <div class="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
        <div class="flex items-center gap-2.5">
          <span class="h-3 w-3 rounded-full bg-cyan-500"></span>
          <h2 id="modal-title" class="text-base font-bold tracking-tight text-slate-100">
            Start New Audit Session
          </h2>
        </div>
        <button
          type="button"
          :disabled="creating"
          @click="closeModal"
          class="text-slate-400 hover:text-slate-200 text-lg leading-none p-1 rounded hover:bg-slate-800 transition-colors disabled:opacity-50"
          aria-label="Close dialog"
        >
          &times;
        </button>
      </div>

      <!-- Modal Body -->
      <form @submit.prevent="handleSubmit" class="p-6 space-y-5 overflow-y-auto max-h-[80vh]">
        <!-- RFC 9457 Error Callout -->
        <div
          v-if="error"
          data-testid="modal-error-callout"
          class="p-4 rounded-md bg-rose-950/60 border border-rose-800/80 text-rose-200 text-sm"
          role="alert"
        >
          <div class="flex items-start gap-2.5">
            <svg
              class="h-5 w-5 text-rose-400 mt-0.5 shrink-0"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              stroke-width="2"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
              />
            </svg>
            <div class="flex-1">
              <h3 class="font-semibold text-rose-200 leading-tight">
                {{ error.title || 'Policy or Validation Error' }}
              </h3>
              <p v-if="error.detail" class="mt-1 text-xs text-rose-300 leading-relaxed">
                {{ error.detail }}
              </p>

              <!-- Field-level validation errors (RFC 9457 invalidParams extension) -->
              <ul
                v-if="error.invalidParams && error.invalidParams.length > 0"
                class="mt-2 space-y-1 text-xs list-disc list-inside text-rose-300"
              >
                <li
                  v-for="param in error.invalidParams"
                  :key="param.name"
                  data-testid="invalid-param-item"
                >
                  <span class="font-mono font-medium">{{ param.name }}</span>: {{ param.reason }}
                </li>
              </ul>
            </div>
          </div>
        </div>

        <!-- Target URL Input -->
        <div>
          <label for="target-url" class="block text-xs font-mono font-medium text-slate-300 mb-1.5">
            Target URL <span class="text-rose-400">*</span>
          </label>
          <input
            id="target-url"
            v-model="targetUrl"
            type="text"
            required
            :disabled="creating"
            placeholder="https://example.com or http://localhost:8080"
            data-testid="target-url-input"
            class="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-100 text-sm placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          />
          <p class="mt-1 text-[11px] text-slate-400">
            Specify the full target URL including scheme (e.g. https:// or http://).
          </p>
        </div>

        <!-- Target Environment Mode Selector -->
        <div>
          <label class="block text-xs font-mono font-medium text-slate-300 mb-2">
            Target Environment Mode <span class="text-rose-400">*</span>
          </label>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <!-- PUBLIC Mode Radio Card -->
            <label
              :class="[
                'flex flex-col p-3 rounded-lg border cursor-pointer transition-all',
                mode === 'PUBLIC'
                  ? 'bg-cyan-950/30 border-cyan-500/70 shadow-sm shadow-cyan-900/30'
                  : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
              ]"
            >
              <div class="flex items-center gap-2 mb-1.5">
                <input
                  type="radio"
                  v-model="mode"
                  value="PUBLIC"
                  name="session-mode"
                  :disabled="creating"
                  data-testid="mode-public-radio"
                  class="text-cyan-600 focus:ring-cyan-500 h-4 w-4 border-slate-700 bg-slate-900"
                />
                <span class="text-xs font-bold text-slate-100 tracking-wide">PUBLIC (Default)</span>
                <span class="text-[10px] px-1.5 py-0.2 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-300 font-mono">
                  Internet
                </span>
              </div>
              <p class="text-[11px] text-slate-400 leading-relaxed ml-6">
                Blocks RFC 1918 private IPs, Loopback, Link-Local, and Cloud Metadata.
              </p>
            </label>

            <!-- LOCAL Mode Radio Card -->
            <label
              :class="[
                'flex flex-col p-3 rounded-lg border cursor-pointer transition-all',
                mode === 'LOCAL'
                  ? 'bg-amber-950/30 border-amber-500/70 shadow-sm shadow-amber-900/30'
                  : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
              ]"
            >
              <div class="flex items-center gap-2 mb-1.5">
                <input
                  type="radio"
                  v-model="mode"
                  value="LOCAL"
                  name="session-mode"
                  :disabled="creating"
                  data-testid="mode-local-radio"
                  class="text-amber-500 focus:ring-amber-500 h-4 w-4 border-slate-700 bg-slate-900"
                />
                <span class="text-xs font-bold text-slate-100 tracking-wide">LOCAL</span>
                <span class="text-[10px] px-1.5 py-0.2 rounded bg-amber-950 border border-amber-500/40 text-amber-300 font-mono">
                  Lab
                </span>
              </div>
              <p class="text-[11px] text-slate-400 leading-relaxed ml-6">
                Allows Loopback & RFC 1918 internal lab targets; strictly blocks Cloud Metadata.
              </p>
            </label>
          </div>
        </div>

        <!-- Mandatory Legal & Scope Attestation Box -->
        <div class="p-4 rounded-lg bg-slate-950/90 border border-slate-800">
          <div class="flex items-center justify-between mb-2">
            <span class="text-xs font-semibold uppercase tracking-wider text-amber-400 flex items-center gap-1.5">
              <i class="pi pi-shield text-xs"></i>
              Legal & Scope Attestation Gate
            </span>
            <span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono border border-slate-700">
              v{{ CANONICAL_SCOPE_ACK_VERSION }}
            </span>
          </div>

          <p class="text-xs text-slate-300 leading-relaxed font-sans italic border-l-2 border-amber-500/60 pl-3 my-2">
            "{{ CANONICAL_SCOPE_ACK_STATEMENT }}"
          </p>

          <div class="mt-3 pt-3 border-t border-slate-800/80">
            <label class="flex items-start gap-2.5 cursor-pointer select-none">
              <input
                type="checkbox"
                v-model="scopeAcknowledged"
                :disabled="creating"
                data-testid="scope-ack-checkbox"
                class="mt-0.5 h-4 w-4 text-cyan-600 focus:ring-cyan-500 border-slate-700 rounded bg-slate-900"
              />
              <span class="text-xs font-medium text-slate-200 leading-snug">
                I explicitly acknowledge and attest to target authorization.
              </span>
            </label>
          </div>
        </div>

        <!-- Action Buttons -->
        <div class="pt-2 flex items-center justify-end gap-3 border-t border-slate-800">
          <button
            type="button"
            :disabled="creating"
            @click="closeModal"
            data-testid="cancel-session-button"
            class="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 active:bg-slate-600 text-slate-300 hover:text-white text-xs font-medium transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Cancel
          </button>
          <button
            type="submit"
            :disabled="!canSubmit"
            data-testid="submit-session-button"
            class="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 text-white font-medium text-xs tracking-wide shadow-sm disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center gap-2"
          >
            <span
              v-if="creating"
              class="h-3 w-3 border-2 border-white/30 border-t-white rounded-full animate-spin"
            ></span>
            <span>Initialize & Enter Workspace</span>
          </button>
        </div>
      </form>
    </div>
  </div>
</template>
