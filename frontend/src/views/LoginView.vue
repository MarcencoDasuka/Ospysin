<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { storeToRefs } from 'pinia'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()
const { status, error } = storeToRefs(authStore)

const username = ref('')
const password = ref('')
const isSubmitting = computed(() => status.value === 'loading')

onMounted(() => {
  authStore.clearError()
})

async function handleLogin() {
  if (isSubmitting.value || !username.value.trim() || !password.value) {
    return
  }

  try {
    await authStore.login({
      username: username.value.trim(),
      password: password.value
    })

    const redirectTarget = route.query.redirect
    if (
      typeof redirectTarget === 'string' &&
      redirectTarget.startsWith('/') &&
      !redirectTarget.startsWith('//')
    ) {
      await router.push(redirectTarget)
    } else {
      await router.push('/')
    }
  } catch {
    // Error is captured in authStore.error and rendered via RFC 9457 error callout
  }
}
</script>

<template>
  <div class="min-h-screen bg-slate-950 flex flex-col items-center justify-center p-4">
    <div class="w-full max-w-md bg-slate-900 border border-slate-800 rounded-lg shadow-2xl p-8">
      <!-- Header -->
      <div class="mb-6 border-b border-slate-800 pb-4">
        <div class="flex items-center gap-2 mb-1">
          <span class="h-3 w-3 rounded-full bg-cyan-500"></span>
          <h1 class="text-lg font-bold tracking-tight text-slate-100">
            Ospysin — Operator Authentication
          </h1>
        </div>
        <p class="text-xs text-slate-400">
          Enter authorized administrative or auditor credentials to access the workspace.
        </p>
      </div>

      <!-- RFC 9457 Error Callout -->
      <div
        v-if="error"
        data-testid="error-callout"
        class="mb-6 p-4 rounded-md bg-rose-950/60 border border-rose-800/80 text-rose-200 text-sm"
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
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <div class="flex-1">
            <h3 class="font-semibold text-rose-200 leading-tight">
              {{ error.title || 'Authentication Failed' }}
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

      <!-- Login Form -->
      <form @submit.prevent="handleLogin" class="space-y-4">
        <div>
          <label for="username" class="block text-xs font-mono font-medium text-slate-300 mb-1.5">
            Username
          </label>
          <input
            id="username"
            v-model="username"
            name="username"
            type="text"
            autocomplete="username"
            required
            :disabled="isSubmitting"
            placeholder="admin"
            data-testid="username-input"
            class="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-100 text-sm placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          />
        </div>

        <div>
          <label for="password" class="block text-xs font-mono font-medium text-slate-300 mb-1.5">
            Password
          </label>
          <input
            id="password"
            v-model="password"
            name="password"
            type="password"
            autocomplete="current-password"
            required
            :disabled="isSubmitting"
            placeholder="••••••••••••••••"
            data-testid="password-input"
            class="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-100 text-sm placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          />
        </div>

        <div class="pt-2 flex justify-end">
          <button
            type="submit"
            data-testid="signin-button"
            :disabled="isSubmitting || !username.trim() || !password"
            class="px-5 py-2 rounded bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 text-white font-medium text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 shadow-sm cursor-pointer"
          >
            <span
              v-if="isSubmitting"
              class="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin"
            ></span>
            <span>{{ isSubmitting ? 'Authenticating...' : 'Sign In' }}</span>
          </button>
        </div>
      </form>
    </div>
  </div>
</template>
