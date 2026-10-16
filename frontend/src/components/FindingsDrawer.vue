<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useWorkspaceStore } from '@/stores/workspace'
import { useSessionsStore } from '@/stores/sessions'
import type { FindingSeverity, FindingConfidence, CreateFindingRequest } from '@/api/types'

const props = defineProps<{
  isOpen: boolean
}>()

const emit = defineEmits<{
  (e: 'close'): void
}>()

const workspaceStore = useWorkspaceStore()
const { findings, loadingFindings, submittingFinding, activeStepDetail } = storeToRefs(workspaceStore)

const sessionsStore = useSessionsStore()
const { currentSession } = storeToRefs(sessionsStore)

const activeFindings = computed(() => {
  return Array.isArray(findings.value)
    ? findings.value.filter((f) => f.status !== 'REJECTED' && f.status !== 'FALSE_POSITIVE')
    : []
})

// Create Finding form state
const showCreateForm = ref(false)
const formObservationId = ref<string | null>(null)
const formTitle = ref('')
const formDescription = ref('')
const formSeverity = ref<FindingSeverity>('MEDIUM')
const formConfidence = ref<FindingConfidence>('FIRM')
const formRemediation = ref('')
const formError = ref<string | null>(null)

// Inline action states
const rejectingFindingId = ref<string | null>(null)
const rejectReasons = ref<Record<string, string>>({})

const attachingEvidenceFindingId = ref<string | null>(null)
const evidenceSnippets = ref<Record<string, string>>({})

function openNewFindingForm(prefill?: {
  observationId?: string
  title?: string
  description?: string
  severity?: FindingSeverity
  confidence?: FindingConfidence
}) {
  formObservationId.value = prefill?.observationId || null
  formTitle.value = prefill?.title || ''
  formDescription.value = prefill?.description || ''
  formSeverity.value = prefill?.severity || 'MEDIUM'
  formConfidence.value = prefill?.confidence || (prefill?.observationId ? 'FIRM' : 'TENTATIVE')
  formRemediation.value = ''
  formError.value = null
  showCreateForm.value = true
}

function closeCreateForm() {
  showCreateForm.value = false
  formObservationId.value = null
  formTitle.value = ''
  formDescription.value = ''
  formRemediation.value = ''
  formError.value = null
}

watch(
  [() => props.isOpen, () => currentSession.value?.id],
  ([newIsOpen, newSessionId], [, oldSessionId]) => {
    if (!newIsOpen || (newSessionId && newSessionId !== oldSessionId)) {
      closeCreateForm()
      rejectingFindingId.value = null
      attachingEvidenceFindingId.value = null
      rejectReasons.value = {}
      evidenceSnippets.value = {}
    }
  }
)

async function handleCreateFinding() {
  if (!currentSession.value || !formTitle.value.trim() || !formDescription.value.trim()) {
    formError.value = 'Title and Description are required.'
    return
  }

  const payload: CreateFindingRequest = {
    observationId: formObservationId.value || null,
    title: formTitle.value.trim(),
    description: formDescription.value.trim(),
    severity: formSeverity.value,
    confidence: formConfidence.value,
    remediation: formRemediation.value.trim() || null
  }

  try {
    await workspaceStore.createFinding(currentSession.value.id, payload)
    closeCreateForm()
  } catch (err: unknown) {
    formError.value = err instanceof Error ? err.message : 'Failed to create finding'
  }
}

async function handleConfirmFinding(findingId: string) {
  if (!currentSession.value) return
  try {
    await workspaceStore.updateFinding(currentSession.value.id, findingId, { status: 'CONFIRMED' })
  } catch {
    // Handled in store
  }
}

async function handleFalsePositiveFinding(findingId: string) {
  if (!currentSession.value) return
  try {
    await workspaceStore.updateFinding(currentSession.value.id, findingId, { status: 'FALSE_POSITIVE' })
  } catch {
    // Handled in store
  }
}

function toggleReject(findingId: string) {
  if (rejectingFindingId.value === findingId) {
    rejectingFindingId.value = null
  } else {
    rejectingFindingId.value = findingId
    if (!rejectReasons.value[findingId]) {
      rejectReasons.value[findingId] = ''
    }
  }
}

async function handleRejectSubmit(findingId: string) {
  if (!currentSession.value) return
  const reason = rejectReasons.value[findingId]?.trim()
  if (!reason) return

  try {
    await workspaceStore.updateFinding(currentSession.value.id, findingId, {
      status: 'REJECTED',
      rejectionReason: reason
    })
    rejectingFindingId.value = null
  } catch {
    // Handled in store
  }
}

function toggleAttachEvidence(findingId: string) {
  if (attachingEvidenceFindingId.value === findingId) {
    attachingEvidenceFindingId.value = null
  } else {
    attachingEvidenceFindingId.value = findingId
    if (!evidenceSnippets.value[findingId]) {
      evidenceSnippets.value[findingId] = ''
    }
  }
}

async function handleEvidenceSubmit(findingId: string) {
  if (!currentSession.value) return
  const snippet = evidenceSnippets.value[findingId]?.trim()
  if (!snippet) return

  const resultId = activeStepDetail.value?.resultId || activeStepDetail.value?.executionId
  if (!resultId) return

  try {
    await workspaceStore.addEvidence(currentSession.value.id, findingId, {
      resultId,
      snippet
    })
    evidenceSnippets.value[findingId] = ''
    attachingEvidenceFindingId.value = null
  } catch {
    // Handled in store
  }
}

defineExpose({
  openNewFindingForm
})
</script>

<template>
  <aside
    v-if="isOpen"
    data-testid="findings-drawer"
    class="fixed inset-y-0 right-0 z-50 w-full sm:w-[480px] bg-slate-900 border-l border-slate-800 shadow-2xl flex flex-col overflow-hidden"
  >
    <!-- Drawer Header -->
    <div class="px-5 py-4 border-b border-slate-800 flex items-center justify-between shrink-0 bg-slate-950">
      <div class="flex items-center gap-2.5">
        <i class="pi pi-shield text-cyan-400 text-base"></i>
        <h3 class="text-sm font-bold uppercase tracking-wider text-slate-200 font-mono">
          Curated Findings
        </h3>
        <span
          class="px-2 py-0.5 rounded-full text-[11px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800/60"
        >
          {{ activeFindings.length }}
        </span>
      </div>

      <div class="flex items-center gap-2">
        <button
          type="button"
          data-testid="new-finding-button"
          :disabled="currentSession?.state === 'ABORTED' || showCreateForm"
          @click="openNewFindingForm()"
          class="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-semibold font-mono transition-colors disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1"
        >
          <i class="pi pi-plus text-xs"></i>
          <span>Manual Finding</span>
        </button>

        <button
          type="button"
          data-testid="close-findings-drawer-button"
          @click="emit('close')"
          class="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          title="Close Drawer"
        >
          <i class="pi pi-times text-sm"></i>
        </button>
      </div>
    </div>

    <!-- Drawer Body -->
    <div class="flex-1 overflow-y-auto p-5 space-y-4">
      <!-- Create Finding Form -->
      <div
        v-if="showCreateForm"
        data-testid="finding-create-form"
        class="p-4 rounded-lg bg-slate-950 border border-cyan-800/80 space-y-3"
      >
        <div class="flex items-center justify-between">
          <h4 class="text-xs font-mono font-bold text-cyan-300 uppercase tracking-wider">
            {{ formObservationId ? 'Promote Observation to Finding' : 'Create Manual Finding' }}
          </h4>
          <button
            type="button"
            @click="closeCreateForm"
            class="text-xs text-slate-400 hover:text-slate-200"
          >
            Cancel
          </button>
        </div>

        <div v-if="formError" class="text-xs text-rose-400 font-mono">{{ formError }}</div>

        <!-- Title -->
        <div class="space-y-1">
          <label class="text-[11px] font-mono uppercase text-slate-400">Title *</label>
          <input
            type="text"
            data-testid="finding-title-input"
            v-model="formTitle"
            placeholder="e.g. Missing Content-Security-Policy header"
            class="w-full px-3 py-1.5 text-xs rounded bg-slate-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <!-- Severity & Confidence Row -->
        <div class="grid grid-cols-2 gap-3">
          <div class="space-y-1">
            <label class="text-[11px] font-mono uppercase text-slate-400">Severity *</label>
            <select
              data-testid="finding-severity-select"
              v-model="formSeverity"
              class="w-full px-3 py-1.5 text-xs rounded bg-slate-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
              <option value="INFO">INFO</option>
            </select>
          </div>

          <div class="space-y-1">
            <label class="text-[11px] font-mono uppercase text-slate-400">Confidence</label>
            <select
              data-testid="finding-confidence-select"
              v-model="formConfidence"
              class="w-full px-3 py-1.5 text-xs rounded bg-slate-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="CERTAIN">CERTAIN</option>
              <option value="FIRM">FIRM</option>
              <option value="TENTATIVE">TENTATIVE</option>
            </select>
          </div>
        </div>

        <!-- Description -->
        <div class="space-y-1">
          <label class="text-[11px] font-mono uppercase text-slate-400">Description *</label>
          <textarea
            data-testid="finding-description-input"
            v-model="formDescription"
            rows="3"
            placeholder="Detailed description of the finding..."
            class="w-full px-3 py-1.5 text-xs rounded bg-slate-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          ></textarea>
        </div>

        <!-- Remediation -->
        <div class="space-y-1">
          <label class="text-[11px] font-mono uppercase text-slate-400">Remediation Guidance</label>
          <textarea
            data-testid="finding-remediation-input"
            v-model="formRemediation"
            rows="2"
            placeholder="Recommended remediation steps..."
            class="w-full px-3 py-1.5 text-xs rounded bg-slate-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          ></textarea>
        </div>

        <!-- Submit Button -->
        <div class="pt-1">
          <button
            type="button"
            data-testid="finding-submit-button"
            :disabled="submittingFinding || !formTitle.trim() || !formDescription.trim()"
            @click="handleCreateFinding"
            class="w-full py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold font-mono text-xs transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {{ submittingFinding ? 'Saving Finding...' : 'Save Finding' }}
          </button>
        </div>
      </div>

      <!-- Findings List -->
      <div data-testid="findings-list" class="space-y-3">
        <!-- Loading State -->
        <div v-if="loadingFindings" class="text-center py-8 text-xs text-slate-500 font-mono">
          Loading findings...
        </div>

        <!-- Empty State -->
        <div
          v-else-if="findings.length === 0"
          data-testid="findings-empty-state"
          class="p-8 text-center rounded-lg bg-slate-950/60 border border-dashed border-slate-800 text-slate-500 text-xs font-mono space-y-2"
        >
          <i class="pi pi-shield text-2xl text-slate-600"></i>
          <div>No findings curated for this session yet.</div>
          <div class="text-[11px] text-slate-600">
            Promote an automated observation from a completed tool execution or create a manual finding above.
          </div>
        </div>

        <!-- Finding Cards -->
        <div
          v-for="finding in findings"
          :key="finding.id"
          :data-testid="'finding-card-' + finding.id"
          class="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3"
        >
          <!-- Card Header & Badges -->
          <div class="flex items-start justify-between gap-2">
            <div class="flex-1 min-w-0">
              <h5 class="text-xs font-bold text-slate-200 break-words">{{ finding.title }}</h5>
            </div>
            <div class="flex items-center gap-1.5 shrink-0">
              <span
                :class="[
                  'text-[9px] px-1.5 py-0.5 rounded font-mono font-bold uppercase tracking-wider border',
                  finding.severity === 'CRITICAL'
                    ? 'bg-red-950 text-red-300 border-red-700'
                    : finding.severity === 'HIGH'
                      ? 'bg-rose-950 text-rose-300 border-rose-700'
                      : finding.severity === 'MEDIUM'
                        ? 'bg-amber-950 text-amber-300 border-amber-700'
                        : finding.severity === 'LOW'
                          ? 'bg-sky-950 text-sky-300 border-sky-700'
                          : 'bg-slate-800 text-slate-300 border-slate-700'
                ]"
              >
                {{ finding.severity }}
              </span>

              <span
                class="text-[9px] px-1.5 py-0.5 rounded font-mono uppercase bg-slate-900 text-slate-400 border border-slate-800"
              >
                {{ finding.confidence }}
              </span>

              <span
                :class="[
                  'text-[9px] px-1.5 py-0.5 rounded font-mono font-bold uppercase tracking-wider border',
                  finding.status === 'CONFIRMED'
                    ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
                    : finding.status === 'REJECTED'
                      ? 'bg-rose-950 text-rose-400 border-rose-800'
                      : finding.status === 'FALSE_POSITIVE'
                        ? 'bg-slate-800 text-slate-400 border-slate-700'
                        : 'bg-cyan-950 text-cyan-300 border-cyan-800'
                ]"
              >
                {{ finding.status }}
              </span>
            </div>
          </div>

          <!-- Description -->
          <p class="text-xs text-slate-300 font-mono whitespace-pre-wrap leading-relaxed">
            {{ finding.description }}
          </p>

          <!-- Remediation (if present) -->
          <div
            v-if="finding.remediation"
            class="p-2 rounded bg-emerald-950/40 border border-emerald-900/60 text-emerald-200 text-xs font-mono space-y-1"
          >
            <div class="text-[10px] uppercase font-bold text-emerald-400">Remediation:</div>
            <div>{{ finding.remediation }}</div>
          </div>

          <!-- Rejection Reason (if REJECTED) -->
          <div
            v-if="finding.status === 'REJECTED' && finding.rejectionReason"
            class="p-2 rounded bg-rose-950/40 border border-rose-900/60 text-rose-200 text-xs font-mono space-y-1"
          >
            <div class="text-[10px] uppercase font-bold text-rose-400">Rejection Reason:</div>
            <div>{{ finding.rejectionReason }}</div>
          </div>

          <!-- Linked Evidence List -->
          <div
            :data-testid="'finding-evidence-list-' + finding.id"
            class="space-y-1.5 pt-2 border-t border-slate-900"
          >
            <div class="text-[10px] font-mono uppercase font-bold text-slate-400 flex items-center justify-between">
              <span>Linked Evidence ({{ finding.evidence?.length || 0 }})</span>
            </div>

            <div
              v-for="ev in finding.evidence || []"
              :key="ev.id"
              class="p-2 rounded bg-slate-900 border border-slate-800 text-xs font-mono space-y-1"
            >
              <div class="text-[10px] text-cyan-400 truncate">
                Tool: {{ ev.toolId }} &bull; {{ new Date(ev.createdAt).toLocaleTimeString() }}
              </div>
              <pre class="text-[11px] text-slate-300 whitespace-pre-wrap break-all">{{ ev.snippet }}</pre>
            </div>
          </div>

          <!-- Curation Actions (when not terminal and session not aborted) -->
          <div
            v-if="
              finding.status !== 'REJECTED' &&
              finding.status !== 'FALSE_POSITIVE' &&
              currentSession?.state !== 'ABORTED'
            "
            class="pt-2 border-t border-slate-900 flex flex-wrap items-center gap-2"
          >
            <!-- When OPEN: Confirm & False Positive -->
            <button
              v-if="finding.status === 'OPEN'"
              type="button"
              :data-testid="'confirm-finding-' + finding.id"
              :disabled="submittingFinding"
              @click="handleConfirmFinding(finding.id)"
              class="px-2.5 py-1 rounded bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-800 text-xs font-mono font-medium transition-colors disabled:opacity-40"
            >
              Confirm
            </button>

            <button
              v-if="finding.status === 'OPEN'"
              type="button"
              :data-testid="'fp-finding-' + finding.id"
              :disabled="submittingFinding"
              @click="handleFalsePositiveFinding(finding.id)"
              class="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 border border-slate-700 text-xs font-mono font-medium transition-colors disabled:opacity-40"
            >
              False Positive
            </button>

            <!-- Reject Toggle -->
            <button
              type="button"
              :data-testid="'reject-finding-toggle-' + finding.id"
              @click="toggleReject(finding.id)"
              class="px-2.5 py-1 rounded bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 text-xs font-mono font-medium transition-colors"
            >
              {{ rejectingFindingId === finding.id ? 'Cancel Reject' : 'Reject' }}
            </button>

            <!-- Attach Evidence Toggle -->
            <button
              type="button"
              :data-testid="'add-evidence-toggle-' + finding.id"
              :disabled="!(activeStepDetail && activeStepDetail.status === 'COMPLETED' && (activeStepDetail.resultId || activeStepDetail.executionId))"
              @click="toggleAttachEvidence(finding.id)"
              class="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-950 text-cyan-300 border border-slate-700 hover:border-cyan-800 text-xs font-mono font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed ml-auto"
              title="Attach raw snippet from currently active completed step"
            >
              {{ attachingEvidenceFindingId === finding.id ? 'Cancel Evidence' : '+ Attach Evidence' }}
            </button>
          </div>

          <!-- Inline Rejection Input -->
          <div
            v-if="rejectingFindingId === finding.id"
            class="p-2.5 rounded bg-rose-950/40 border border-rose-900/80 space-y-2"
          >
            <label class="text-[10px] font-mono uppercase font-bold text-rose-300">
              Rejection Reason (Required) *
            </label>
            <input
              type="text"
              :data-testid="'reject-reason-input-' + finding.id"
              v-model="rejectReasons[finding.id]"
              placeholder="Reason for rejecting this finding..."
              class="w-full px-2.5 py-1 text-xs rounded bg-slate-900 border border-rose-800 text-slate-200 focus:outline-none font-mono"
            />
            <div class="flex justify-end gap-2">
              <button
                type="button"
                :data-testid="'reject-finding-submit-' + finding.id"
                :disabled="!rejectReasons[finding.id]?.trim() || submittingFinding"
                @click="handleRejectSubmit(finding.id)"
                class="px-3 py-1 rounded bg-rose-700 hover:bg-rose-600 text-white text-xs font-mono font-bold transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Confirm Rejection
              </button>
            </div>
          </div>

          <!-- Inline Attach Evidence Input -->
          <div
            v-if="attachingEvidenceFindingId === finding.id"
            class="p-2.5 rounded bg-slate-900 border border-cyan-800/80 space-y-2"
          >
            <label class="text-[10px] font-mono uppercase font-bold text-cyan-300">
              Evidence Snippet (from active step) *
            </label>
            <textarea
              :data-testid="'evidence-snippet-input-' + finding.id"
              v-model="evidenceSnippets[finding.id]"
              rows="3"
              placeholder="Paste raw output snippet proving this finding..."
              class="w-full px-2.5 py-1 text-xs rounded bg-slate-950 border border-slate-700 text-slate-200 focus:outline-none font-mono"
            ></textarea>
            <div class="flex justify-end gap-2">
              <button
                type="button"
                :data-testid="'evidence-submit-' + finding.id"
                :disabled="!evidenceSnippets[finding.id]?.trim() || submittingFinding"
                @click="handleEvidenceSubmit(finding.id)"
                class="px-3 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-mono font-bold transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Save Evidence
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </aside>
</template>
