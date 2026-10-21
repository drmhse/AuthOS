<template>
  <div class="account-security-controls stack-lg">
    <div v-if="message" class="alert" :class="messageType === 'success' ? 'alert-success' : 'alert-error'">
      {{ message }}
    </div>

    <AccountProfileCard
      :account-email="accountEmail"
      :email-editable="!authStore.user?.is_platform_owner"
      :account-mfa-code="accountMfaCode"
      :mfa-enabled="Boolean(mfaStatus?.enabled)"
      :password-form="passwordForm"
      :account-saving="accountSaving"
      :password-saving="passwordSaving"
      @update:account-email="accountEmail = $event"
      @update:account-mfa-code="accountMfaCode = $event"
      @update:password-form="passwordForm = $event"
      @save-account="saveAccount"
      @change-password="changePassword"
    />

    <SecurityMfaCard
      :mfa-status="mfaStatus"
      :mfa-setup="mfaSetup"
      :mfa-code="mfaCode"
      :backup-codes="backupCodes"
      @update:mfa-code="mfaCode = $event"
      @start-setup="startMfaSetup"
      @complete-setup="completeMfaSetup"
      @disable="openDisableMfaDialog"
      @regenerate-backups="openRegenerateBackupDialog"
    />

    <SecurityPasskeysCard
      :passkeys="passkeys"
      @register="openRegisterPasskeyDialog"
      @rename="openRenamePasskeyDialog"
      @delete="openDeletePasskeyDialog"
    />

    <SecurityDevicesCard
      :devices="devices"
      @rename="openRenameDeviceDialog"
      @revoke="openRevokeDeviceDialog"
    />

    <BaseDialog
      :open="dialog.open"
      :title="dialog.title"
      :description="dialog.description"
      :close-label="'Cancel'"
      @close="closeDialog"
    >
      <div v-if="dialog.inputLabel" class="field">
        <label for="security-dialog-input">{{ dialog.inputLabel }}</label>
        <input
          id="security-dialog-input"
          v-model="dialog.inputValue"
          class="input"
          :type="dialog.inputType || 'text'"
        />
      </div>

      <template #actions>
        <BaseButton
          :variant="dialogConfirmVariant"
          :loading="dialogBusy"
          :disabled="dialog.requireInput !== false && Boolean(dialog.inputLabel) && !dialog.inputValue.trim()"
          @click="confirmDialog"
        >
          {{ dialog.confirmLabel }}
        </BaseButton>
      </template>
    </BaseDialog>
  </div>
</template>

<script setup>
import { ref, toRef, watch } from 'vue';
import BaseDialog from '@/components/BaseDialog.vue';
import BaseButton from '@/components/BaseButton.vue';
import AccountProfileCard from '@/features/workspace/components/security/AccountProfileCard.vue';
import SecurityDevicesCard from '@/features/workspace/components/security/SecurityDevicesCard.vue';
import SecurityMfaCard from '@/features/workspace/components/security/SecurityMfaCard.vue';
import SecurityPasskeysCard from '@/features/workspace/components/security/SecurityPasskeysCard.vue';
import { useSecurityCenter } from '@/features/workspace/useSecurityCenter';
import { sso } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';

const props = defineProps({
  refreshVersion: { type: Number, default: 0 },
});

const authStore = useAuthStore();
const refreshVersion = toRef(props, 'refreshVersion');

const accountEmail = ref('');
const accountMfaCode = ref('');
const accountSaving = ref(false);
const passwordSaving = ref(false);
const passwordForm = ref({ current: '', next: '' });

const {
  message,
  messageType,
  mfaStatus,
  mfaSetup,
  mfaCode,
  backupCodes,
  passkeys,
  devices,
  dialog,
  dialogBusy,
  dialogConfirmVariant,
  startMfaSetup,
  completeMfaSetup,
  openDisableMfaDialog,
  openRegenerateBackupDialog,
  openRegisterPasskeyDialog,
  openRenamePasskeyDialog,
  openDeletePasskeyDialog,
  openRenameDeviceDialog,
  openRevokeDeviceDialog,
  confirmDialog,
  closeDialog,
  setSuccess,
  setError,
} = useSecurityCenter(refreshVersion);

watch(
  () => [refreshVersion.value, authStore.user?.email],
  () => {
    accountEmail.value = authStore.user?.email || '';
  },
  { immediate: true },
);

async function saveAccount() {
  accountSaving.value = true;

  try {
    await sso.user.updateProfile({
      email: accountEmail.value,
      current_password: passwordForm.value.current || undefined,
      mfa_code: accountMfaCode.value.trim() || undefined,
    });
    await authStore.refreshUser();
    accountMfaCode.value = '';
    setSuccess('Account email updated. Check the new address for a verification link.');
  } catch (error) {
    setError(error.message || 'Failed to update the account email.');
  } finally {
    accountSaving.value = false;
  }
}

async function changePassword() {
  if (passwordForm.value.next.length < 8) {
    setError('Use a new password with at least 8 characters.');
    return;
  }

  passwordSaving.value = true;

  try {
    await sso.user.changePassword({
      current_password: passwordForm.value.current,
      new_password: passwordForm.value.next,
      mfa_code: accountMfaCode.value.trim() || undefined,
    });
    passwordForm.value = { current: '', next: '' };
    accountMfaCode.value = '';
    setSuccess('Password changed.');
  } catch (error) {
    setError(error.message || 'Failed to change password.');
  } finally {
    passwordSaving.value = false;
  }
}
</script>
