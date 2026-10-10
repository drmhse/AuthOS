<template>
  <AuthShell
    title="Confirming your email"
    description="We’re verifying the email address attached to this AuthOS account."
  >
    <div class="stack">
      <AuthStatusPanel
        :status="loading ? 'loading' : message ? 'success' : 'error'"
        loading-text="Verifying your email address..."
        :success-text="message"
        :error-text="errorMessage"
      />

      <p class="muted auth-centered-copy">
        <router-link :to="authRouteWithContext(route, '/')">Back to sign in</router-link>
      </p>
    </div>
  </AuthShell>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import AuthShell from '@/components/AuthShell.vue';
import { formatResponseErrorPayload } from '@/features/auth/errors';
import AuthStatusPanel from '@/features/auth/components/AuthStatusPanel.vue';
import { authRouteWithContext } from '@/utils/authFlowContext';
import { scrubCurrentUrl } from '@/utils/urlSecurity';

const route = useRoute();
const router = useRouter();
const loading = ref(true);
const message = ref('');
const errorMessage = ref('');
const token = Array.isArray(route.query.token) ? route.query.token[0] : route.query.token;

onMounted(async () => {
  if (!token) {
    loading.value = false;
    errorMessage.value = 'Missing verification token.';
    return;
  }

  scrubCurrentUrl({ queryKeys: ['token'] });

  try {
    const response = await fetch(`/auth/verify-email?token=${encodeURIComponent(String(token))}`);
    if (!response.ok) {
      const rawPayload = await response.text();
      throw new Error(
        formatResponseErrorPayload(rawPayload, 'This verification link is invalid or expired.'),
      );
    }
    message.value = 'Email verified. Redirecting to sign in...';
    // Carry the flow context (org/service/redirect/state) plus a verified
    // flag, so the login page can confirm and complete the round trip (A8).
    setTimeout(
      () => router.push(authRouteWithContext(route, '/', { verified: '1' })),
      1400,
    );
  } catch (error) {
    errorMessage.value = error.message || 'Email verification failed.';
  } finally {
    loading.value = false;
  }
});
</script>
