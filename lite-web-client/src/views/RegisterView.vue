<template>
  <AuthShell
    title="Create your account"
    description="Create an AuthOS operator account for hosted sign-in and your organization workspace."
  >
    <div class="stack">
      <div class="auth-provider-grid">
        <BaseButton variant="secondary" block @click="handleOAuthRegister('github')">GitHub</BaseButton>
        <BaseButton variant="secondary" block @click="handleOAuthRegister('google')">Google</BaseButton>
        <BaseButton variant="secondary" block @click="handleOAuthRegister('microsoft')">Microsoft</BaseButton>
      </div>

      <div v-if="message" class="alert alert-success">{{ message }}</div>
      <div v-if="errorMessage" class="alert alert-error">{{ errorMessage }}</div>
      <div v-if="registrationOpen === false" class="alert alert-warning">
        Registration is unavailable: this server can't send email yet. Ask your administrator to configure SMTP.
      </div>

      <div class="field">
        <label for="email">Email address</label>
        <input id="email" v-model="email" type="email" class="input input-lg" placeholder="name@company.com" :disabled="registrationOpen === false" />
      </div>

      <div class="field">
        <label for="password">Password</label>
        <input id="password" v-model="password" type="password" class="input input-lg" placeholder="Minimum 8 characters" :disabled="registrationOpen === false" />
      </div>

      <div class="field">
        <label for="confirm-password">Confirm password</label>
        <input id="confirm-password" v-model="confirmPassword" type="password" class="input input-lg" placeholder="Repeat your password" :disabled="registrationOpen === false" />
      </div>

      <BaseButton :loading="loading" :disabled="registrationOpen === false" block @click="handlePasswordRegister">Create account</BaseButton>

      <p class="muted auth-centered-copy">
        Already have an account?
        <router-link :to="authRouteWithContext(route, '/')">Sign in</router-link>.
      </p>
    </div>
  </AuthShell>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { useRoute } from 'vue-router';
import AuthShell from '@/components/AuthShell.vue';
import BaseButton from '@/components/BaseButton.vue';
import { sso } from '@/lib/api';
import { authRouteWithContext, getAuthFlowContext } from '@/utils/authFlowContext';

const route = useRoute();
const email = ref('');
const password = ref('');
const confirmPassword = ref('');
const loading = ref(false);
const message = ref('');
const errorMessage = ref('');
// Null while probing; false disables the form up front instead of
// failing after submit when SMTP isn't configured (A7).
const registrationOpen = ref(null);

onMounted(async () => {
  try {
    const status = await sso.auth.availability();
    registrationOpen.value = status?.password_registration !== false;
  } catch {
    registrationOpen.value = true;
  }
});

function handleOAuthRegister(provider) {
  const ctx = getAuthFlowContext(route);
  const loginUrl = ctx.isServiceFlow
    ? sso.auth.getLoginUrl(provider, {
        org: ctx.org,
        service: ctx.service,
        redirect_uri: ctx.redirectUri,
      })
    : sso.auth.getAdminLoginUrl(provider);

  window.location.href = loginUrl;
}

async function handlePasswordRegister() {
  if (registrationOpen.value === false) {
    errorMessage.value = 'Registration is unavailable: this server cannot send email yet.';
    return;
  }
  if (!email.value || password.value.length < 8 || password.value !== confirmPassword.value) {
    errorMessage.value = 'Enter a valid email and matching passwords with at least 8 characters.';
    return;
  }

  loading.value = true;
  message.value = '';
  errorMessage.value = '';

  try {
    const ctx = getAuthFlowContext(route);
    const payload = {
      email: email.value,
      password: password.value,
    };

    if (ctx.isServiceFlow) {
      payload.org_slug = ctx.org;
      payload.service_slug = ctx.service;
      payload.redirect_uri = ctx.redirectUri;
    }

    const response = await sso.auth.register(payload);
    message.value = response?.message || `Verification email sent to ${email.value}.`;
  } catch (error) {
    errorMessage.value = error.message || 'Registration failed.';
  } finally {
    loading.value = false;
  }
}
</script>
