<template>
  <section class="workspace-card stack">
    <div class="section-header">
      <div>
        <h2 class="section-title">Account Profile</h2>
        <p class="section-copy">Update the active account email and rotate the password from one place.</p>
      </div>
    </div>

    <div class="field">
      <label for="account-email">Email address</label>
      <input
        id="account-email"
        :value="accountEmail"
        type="email"
        class="input"
        :disabled="!emailEditable"
        @input="$emit('update:accountEmail', $event.target.value)"
      />
      <p v-if="!emailEditable" class="field-hint">
        Platform-owner email changes are managed through platform configuration.
      </p>
    </div>

    <div class="field">
      <label for="current-password">Current password</label>
      <input
        id="current-password"
        :value="passwordForm.current"
        type="password"
        autocomplete="current-password"
        class="input"
        @input="$emit('update:passwordForm', { ...passwordForm, current: $event.target.value })"
      />
    </div>

    <div v-if="mfaEnabled" class="field">
      <label for="account-mfa-code">Authenticator or backup code</label>
      <input
        id="account-mfa-code"
        :value="accountMfaCode"
        type="text"
        autocomplete="one-time-code"
        class="input code"
        maxlength="32"
        placeholder="Required for account changes"
        @input="$emit('update:accountMfaCode', $event.target.value)"
      />
    </div>

    <BaseButton :loading="accountSaving" :disabled="!emailEditable" @click="$emit('save-account')">
      Save account details
    </BaseButton>

    <div class="field">
      <label for="new-password">New password</label>
      <input
        id="new-password"
        :value="passwordForm.next"
        type="password"
        class="input"
        placeholder="Minimum 8 characters"
        @input="$emit('update:passwordForm', { ...passwordForm, next: $event.target.value })"
      />
    </div>

    <BaseButton :loading="passwordSaving" @click="$emit('change-password')">
      Change password
    </BaseButton>
  </section>
</template>

<script setup>
import BaseButton from '@/components/BaseButton.vue';

defineProps({
  accountEmail: { type: String, default: '' },
  emailEditable: { type: Boolean, default: true },
  accountMfaCode: { type: String, default: '' },
  mfaEnabled: { type: Boolean, default: false },
  passwordForm: {
    type: Object,
    default: () => ({ current: '', next: '' }),
  },
  accountSaving: { type: Boolean, default: false },
  passwordSaving: { type: Boolean, default: false },
});

defineEmits([
  'update:accountEmail',
  'update:accountMfaCode',
  'update:passwordForm',
  'save-account',
  'change-password',
]);
</script>
