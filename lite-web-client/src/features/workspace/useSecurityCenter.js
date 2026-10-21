import { computed, ref, watch } from 'vue';
import { sso } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';

export function useSecurityCenter(refreshVersion) {
  const authStore = useAuthStore();
  const message = ref('');
  const messageType = ref('success');
  const mfaStatus = ref(null);
  const mfaSetup = ref(null);
  const mfaCode = ref('');
  const backupCodes = ref([]);
  const passkeys = ref([]);
  const devices = ref([]);
  const dialog = ref(resetDialog());
  const dialogBusy = ref(false);

  const dialogConfirmVariant = computed(() => (dialog.value.destructive ? 'danger' : 'primary'));

  watch(
    () => refreshVersion.value,
    async () => {
      await Promise.all([loadMfaStatus(), loadPasskeys(), loadDevices()]);
    },
    { immediate: true },
  );

  async function loadMfaStatus() {
    mfaStatus.value = await sso.user.mfa.getStatus();
  }

  function startMfaSetup() {
    message.value = '';
    mfaSetup.value = null;
    backupCodes.value = [];
    dialog.value = {
      open: true,
      kind: 'enable-mfa',
      title: 'Enable multi-factor authentication',
      description:
        'Confirm your current password if the account has one. OAuth-only accounts may leave it blank.',
      confirmLabel: 'Continue',
      destructive: false,
      inputLabel: 'Current password (if set)',
      inputType: 'password',
      requireInput: false,
      inputValue: '',
      payload: null,
    };
  }

  async function completeMfaSetup() {
    try {
      const response = await sso.user.mfa.verify(mfaCode.value);
      mfaSetup.value = null;
      mfaCode.value = '';
      backupCodes.value = response.backup_codes || [];
      if (response.access_token && response.refresh_token) {
        await authStore.handleLoginCallback(response.access_token, response.refresh_token);
      }
      setSuccess('MFA enabled. Save the backup codes below.');
      await loadMfaStatus();
    } catch (error) {
      setError(error.message || 'Failed to finish MFA setup.');
    }
  }

  async function loadPasskeys() {
    passkeys.value = await sso.passkeys.list();
  }

  async function loadDevices() {
    const response = await sso.user.devices.list();
    devices.value = response.devices || [];
  }

  function openDisableMfaDialog() {
    dialog.value = {
      open: true,
      kind: 'disable-mfa',
      title: 'Disable MFA?',
      description:
        'Enter a current authenticator or backup code. This removes the extra authentication factor from the account.',
      confirmLabel: 'Disable MFA',
      destructive: true,
      inputLabel: 'Authenticator or backup code',
      inputType: 'text',
      requireInput: true,
      inputValue: '',
      payload: null,
    };
  }

  function openRegenerateBackupDialog() {
    dialog.value = {
      open: true,
      kind: 'regenerate-backups',
      title: 'Regenerate backup codes?',
      description:
        'Enter a current authenticator or backup code. Generating a new set invalidates the current recovery codes immediately.',
      confirmLabel: 'Generate codes',
      destructive: true,
      inputLabel: 'Authenticator or backup code',
      inputType: 'text',
      requireInput: true,
      inputValue: '',
      payload: null,
    };
  }

  function openRegisterPasskeyDialog() {
    dialog.value = {
      open: true,
      kind: 'register-passkey',
      title: 'Register a passkey',
      description: 'Give this passkey a recognizable device name before the browser creates it.',
      confirmLabel: 'Continue',
      destructive: false,
      inputLabel: 'Passkey name',
      inputValue: 'Current device',
      payload: null,
    };
  }

  function openRenamePasskeyDialog(passkey) {
    dialog.value = {
      open: true,
      kind: 'rename-passkey',
      title: 'Rename passkey',
      description: 'Update the display name shown in your security settings.',
      confirmLabel: 'Save name',
      destructive: false,
      inputLabel: 'Passkey name',
      inputValue: passkey.name,
      payload: passkey,
    };
  }

  function openDeletePasskeyDialog(passkey) {
    dialog.value = {
      open: true,
      kind: 'delete-passkey',
      title: 'Delete this passkey?',
      description: `This removes ${passkey.name} from the account and cannot be undone.`,
      confirmLabel: 'Delete passkey',
      destructive: true,
      inputLabel: '',
      inputValue: '',
      payload: passkey,
    };
  }

  function openRenameDeviceDialog(device) {
    dialog.value = {
      open: true,
      kind: 'rename-device',
      title: 'Rename trusted device',
      description: 'Use a name that helps you identify this remembered device later.',
      confirmLabel: 'Save name',
      destructive: false,
      inputLabel: 'Device name',
      inputValue: device.device_name,
      payload: device,
    };
  }

  function openRevokeDeviceDialog(device) {
    dialog.value = {
      open: true,
      kind: 'revoke-device',
      title: 'Revoke trusted device?',
      description: `This removes trust for ${device.device_name} and forces it to sign in again.`,
      confirmLabel: 'Revoke device',
      destructive: true,
      inputLabel: '',
      inputValue: '',
      payload: device,
    };
  }

  async function confirmDialog() {
    dialogBusy.value = true;
    message.value = '';

    try {
      switch (dialog.value.kind) {
        case 'enable-mfa': {
          mfaSetup.value = await sso.user.mfa.setup({
            current_password: dialog.value.inputValue.trim() || undefined,
          });
          break;
        }
        case 'disable-mfa': {
          const response = await sso.user.mfa.disable({
            mfa_code: dialog.value.inputValue.trim(),
          });
          if (response.access_token && response.refresh_token) {
            await authStore.handleLoginCallback(response.access_token, response.refresh_token);
          }
          backupCodes.value = [];
          setSuccess('MFA disabled.');
          await loadMfaStatus();
          break;
        }
        case 'regenerate-backups': {
          const response = await sso.user.mfa.regenerateBackupCodes({
            mfa_code: dialog.value.inputValue.trim(),
          });
          backupCodes.value = response.backup_codes || [];
          setSuccess('Backup codes regenerated.');
          break;
        }
        case 'register-passkey':
          await sso.passkeys.register(dialog.value.inputValue?.trim() || undefined);
          setSuccess('Passkey registered.');
          await loadPasskeys();
          break;
        case 'rename-passkey':
          await sso.passkeys.updateName(dialog.value.payload.id, dialog.value.inputValue.trim());
          setSuccess('Passkey renamed.');
          await loadPasskeys();
          break;
        case 'delete-passkey':
          await sso.passkeys.delete(dialog.value.payload.id);
          setSuccess('Passkey deleted.');
          await loadPasskeys();
          break;
        case 'rename-device':
          await sso.user.devices.updateName(dialog.value.payload.id, dialog.value.inputValue.trim());
          setSuccess('Device renamed.');
          await loadDevices();
          break;
        case 'revoke-device':
          await sso.user.devices.revoke(dialog.value.payload.id);
          setSuccess('Trusted device revoked.');
          await loadDevices();
          break;
        default:
          break;
      }

      closeDialog();
    } catch (error) {
      setError(error.message || 'Security action failed.');
    } finally {
      dialogBusy.value = false;
    }
  }

  function closeDialog() {
    dialog.value = resetDialog();
  }

  function setSuccess(text) {
    messageType.value = 'success';
    message.value = text;
  }

  function setError(text) {
    messageType.value = 'error';
    message.value = text;
  }

  return {
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
    loadMfaStatus,
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
  };
}

function resetDialog() {
  return {
    open: false,
    kind: '',
    title: '',
    description: '',
    confirmLabel: 'Continue',
    destructive: false,
    inputLabel: '',
    inputValue: '',
    payload: null,
  };
}
