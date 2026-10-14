<script setup lang="ts">
import AppHeader from '@/components/AppHeader.vue'
</script>

<template>
  <div class="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
    <!-- Screen 1 Header -->
    <AppHeader />

    <!-- Main Content: Session List Shell (Screen 1) -->
    <main class="flex-1 p-6 max-w-7xl w-full mx-auto">
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
            disabled
            class="px-4 py-2 rounded bg-cyan-600/50 text-white/80 font-medium text-xs tracking-wide cursor-not-allowed border border-cyan-500/30 shadow-sm"
            title="Session setup will be enabled in Phase 8"
          >
            + New Audit Session
          </button>
        </div>
      </div>

      <!-- Placeholder Table Shell -->
      <div class="mt-6 bg-slate-900 border border-slate-800 rounded-lg overflow-hidden shadow-lg">
        <table class="w-full text-left text-xs font-mono">
          <thead class="bg-slate-800/80 text-slate-300 border-b border-slate-700/80 uppercase tracking-wider">
            <tr>
              <th class="px-4 py-3 font-semibold">Target URL</th>
              <th class="px-4 py-3 font-semibold">Mode</th>
              <th class="px-4 py-3 font-semibold">Steps</th>
              <th class="px-4 py-3 font-semibold">Findings</th>
              <th class="px-4 py-3 font-semibold">Created At</th>
              <th class="px-4 py-3 font-semibold text-right">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-800 text-slate-400">
            <tr>
              <td colspan="6" class="px-4 py-12 text-center text-slate-500 font-sans">
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
          </tbody>
        </table>
      </div>
    </main>
  </div>
</template>
