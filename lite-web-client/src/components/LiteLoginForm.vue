<template>
  <div class="stack">
    <div v-if="statusMessage" class="alert" :class="statusClass">{{ statusMessage }}</div>

    <div v-if="authContext.isServiceFlow" class="alert" :class="redirectInvalid ? 'alert-warning' : 'alert-info'">
      Signing in to {{ serviceDisplayName }} for {{ orgDisplayName }}.
      <span v-if="redirectInvalid"> This request has an unregistered return URL.</span>
    </div>

    <LoginEmailStep
      v-if="step === 1"
      v-model="email"
      :providers="providerOptions"
      :loading="lookupLoading"
      @continue="handleEmailLookup"
      @oauth="handleOAuthLogin"
    />

    <LoginPasswordStep
      v-else
      :email="email"
      :password="password"
      :upstream-provider="upstreamProvider"
      :connection-id="connectionId"
      :can-use-magic-link="canUseMagicLink"
      :can-use-passkey="canUsePasskey"
      :magic-link-loading="magicLinkLoading"
      :passkey-loading="passkeyLoading"
      :loading="loading"
      :forgot-password-to="forgotPasswordTo"
      @update:password="password = $event"
      @change-email="resetToEmailStep"
      @oauth="handleOAuthLogin"
      @magic-link="handleMagicLinkRequest"
      @passkey="handlePasskeyLogin"
      @submit="handlePasswordLogin"
    />
  </div>
</template>

<script setup>
import { useRoute, useRouter } from 'vue-router';
import LoginEmailStep from '@/features/auth/components/LoginEmailStep.vue';
import LoginPasswordStep from '@/features/auth/components/LoginPasswordStep.vue';
import { useLoginFlow } from '@/features/auth/useLoginFlow';

const route = useRoute();
const router = useRouter();

const {
  email,
  password,
  step,
  loading,
  lookupLoading,
  magicLinkLoading,
  passkeyLoading,
  statusMessage,
  statusClass,
  upstreamProvider,
  connectionId,
  authContext,
  providerOptions,
  serviceDisplayName,
  orgDisplayName,
  redirectInvalid,
  canUseMagicLink,
  canUsePasskey,
  forgotPasswordTo,
  handleEmailLookup,
  handleOAuthLogin,
  handlePasswordLogin,
  handleMagicLinkRequest,
  handlePasskeyLogin,
  resetToEmailStep,
} = useLoginFlow(route, router);
</script>
