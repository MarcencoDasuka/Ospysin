<script setup lang="ts">
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'
import { useHealthStore } from '@/stores/health'

const router = useRouter()
const authStore = useAuthStore()
const healthStore = useHealthStore()

const { user } = storeToRefs(authStore)
const { isOllamaReady, ollamaStatusText, loading: healthLoading } = storeToRefs(healthStore)

onMounted(async () => {
  await healthStore.checkHealth()
})

async function handleLogout() {
  await authStore.logout()
  await router.push('/login')
}
</script>

<template>
  <header class="bg-slate-900 border-b border-slate-800 px-6 py-3 flex items-center justify-between text-sm select-none">
    <!-- Brand / Title -->
    <div class="flex items-center gap-3">
      <div class="h-8 w-8 rounded bg-cyan-600/20 border border-cyan-500/40 flex items-center justify-center font-bold text-cyan-400">
        O
      </div>
      <div>
        <span class="font-bold text-slate-100 tracking-wide text-base">Ospysin Platform</span>
        <span class="ml-2 text-xs text-slate-400 font-mono">v0.1.0</span>
      </div>
    </div>

    <!-- Right Controls: Operator Profile, Logout, Health Status -->
    <div class="flex items-center gap-6">
      <!-- Operator Info & Logout -->
      <div class="flex items-center gap-3 bg-slate-800/60 px-3 py-1.5 rounded border border-slate-700/50">
        <span class="text-slate-400 font-mono text-xs">
          Operator: <strong class="text-slate-200 font-semibold">{{ user?.username || 'admin' }}</strong>
        </span>
        <button
          type="button"
          data-testid="logout-button"
          @click="handleLogout"
          class="text-xs px-2 py-0.5 rounded bg-slate-700 hover:bg-slate-600 active:bg-slate-500 text-slate-200 hover:text-white transition-colors cursor-pointer"
        >
          [Logout]
        </button>
      </div>

      <!-- Health Status Badge -->
      <div class="flex items-center gap-2">
        <span class="text-xs text-slate-400 font-mono">Status:</span>
        <span
          data-testid="health-badge"
          :class="[
            'text-xs px-2.5 py-1 rounded font-mono font-medium tracking-tight border flex items-center gap-1.5',
            isOllamaReady
              ? 'bg-emerald-950/70 border-emerald-500/40 text-emerald-400'
              : 'bg-rose-950/70 border-rose-500/40 text-rose-400'
          ]"
        >
          <span
            :class="[
              'h-1.5 w-1.5 rounded-full',
              healthLoading
                ? 'bg-amber-400 animate-pulse'
                : isOllamaReady
                  ? 'bg-emerald-400'
                  : 'bg-rose-400'
            ]"
          ></span>
          <span>[{{ ollamaStatusText }}]</span>
        </span>
      </div>
    </div>
  </header>
</template>
