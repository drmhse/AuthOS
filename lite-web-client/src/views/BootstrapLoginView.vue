<template>
  <AuthShell
    title="Preparing your setup session"
    description="This one-time link signs in the platform owner and opens the managed setup workspace."
  >
    <AuthStatusPanel
      :status="status"
      loading-text="Signing in..."
      success-text="Signed in. Redirecting to platform setup..."
      :error-text="errorMessage"
    />
  </AuthShell>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import AuthShell from '@/components/AuthShell.vue';
import AuthStatusPanel from '@/features/auth/components/AuthStatusPanel.vue';
import { sso } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';
import { useAuthFlowStore } from '@/stores/authFlow';

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();
const authFlowStore = useAuthFlowStore();

const status = ref('loading');
const errorMessage = ref('');

onMounted(async () => {
  const token = readBootstrapToken();
  if (!token) {
    status.value = 'error';
    errorMessage.value = 'This bootstrap link is missing its token.';
    return;
  }

  window.history.replaceState({}, document.title, route.path);

  try {
    const response = await fetch('/api/public/bootstrap-login', {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
      },
      body: JSON.stringify({ token }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || 'Bootstrap login failed.');
    }

    // MFA-enrolled owners receive a short-lived pre-auth token instead of a
    // full session. Complete the normal MFA challenge first.
    if (payload.access_token && !payload.refresh_token) {
      authFlowStore.setMfaChallenge({
        preauthToken: payload.access_token,
        redirectPath: '/app/platform-setup',
        supportPath: '/support',
      });
      await router.replace('/mfa-challenge');
      return;
    }

    await authStore.handleLoginCallback(payload.access_token, payload.refresh_token);
    status.value = 'success';

    // Platform controls now require enrolled MFA. Send a new owner to the
    // security center before the setup workspace so enrollment is explicit.
    const mfaStatus = await sso.user.mfa.getStatus();
    await router.replace(mfaStatus.enabled ? '/app/platform-setup' : '/app/account-security');
  } catch (error) {
    status.value = 'error';
    errorMessage.value = error.message || 'Bootstrap login failed.';
  }
});

function readBootstrapToken() {
  const hash = window.location.hash.startsWith('#') ? window.location.hash.slice(1) : window.location.hash;
  return String(new URLSearchParams(hash).get('token') || '').trim();
}
</script>
