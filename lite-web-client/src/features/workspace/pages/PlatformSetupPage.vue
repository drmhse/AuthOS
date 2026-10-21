<template>
  <div class="workspace-page stack-lg">
    <section v-if="!showSetup" class="workspace-card stack">
      <h2 class="section-title">Managed setup is not available</h2>
      <p class="section-copy">
        This AuthOS Lite session does not have access to the standalone configuration workspace.
      </p>
    </section>

    <section v-else-if="!mfaStatusLoaded" class="workspace-card stack">
      <h2 class="section-title">Checking platform security</h2>
      <p class="section-copy">Verifying the MFA state for this session.</p>
    </section>

    <section v-else-if="needsMfaEnrollment" class="workspace-card stack">
      <h2 class="section-title">MFA enrollment required</h2>
      <p class="section-copy">
        Platform controls require multi-factor authentication. Enroll an authenticator app before
        opening the managed setup workspace.
      </p>
      <RouterLink class="text-link" to="/app/account-security">
        Open security settings
      </RouterLink>
    </section>

    <section v-else-if="!mfaReady" class="workspace-card stack">
      <h2 class="section-title">Verify with MFA</h2>
      <p class="section-copy">
        This session signed in without completing the authenticator step. Sign in again with your
        password or magic link and confirm the MFA prompt before opening platform controls.
      </p>
      <RouterLink class="text-link" to="/login">
        Sign in again
      </RouterLink>
    </section>

    <ManagedConfigPanel v-else />
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue';
import { RouterLink } from 'vue-router';
import ManagedConfigPanel from '@/components/ManagedConfigPanel.vue';
import { sso } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';
import { useWorkspaceStore } from '@/stores/workspace';

const authStore = useAuthStore();
const workspaceStore = useWorkspaceStore();
const mfaStatusLoaded = ref(false);
const mfaEnrolled = ref(false);
const mfaReady = ref(false);

const showSetup = computed(() => authStore.isPlatformOwner && authStore.isPlatformContext && workspaceStore.managedConfigEnabled);
const needsMfaEnrollment = computed(() => mfaStatusLoaded.value && !mfaEnrolled.value);
const bootstrapSession = computed(() => authStore.claims?.bootstrap === true);

onMounted(async () => {
  if (!showSetup.value) return;
  try {
    const status = await sso.user.mfa.getStatus();
    mfaEnrolled.value = Boolean(status.enabled);
    mfaStatusLoaded.value = true;
    mfaReady.value = mfaEnrolled.value && (authStore.isMfaVerified || bootstrapSession.value);
  } catch {
    mfaEnrolled.value = false;
    mfaStatusLoaded.value = true;
    mfaReady.value = false;
  }
});
</script>
