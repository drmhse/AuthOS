<template>
  <div class="workspace-page stack-lg">
    <section v-if="workspaceStore.mode === 'loading'" class="workspace-card">
      <LoadingSpinner text="Loading your workspace..." />
    </section>

    <section v-else-if="workspaceStore.mode === 'error'" class="workspace-card stack">
      <h2 class="section-title">Workspace unavailable</h2>
      <div class="alert alert-error">{{ workspaceStore.error }}</div>
      <BaseButton variant="secondary" @click="reload">Try again</BaseButton>
    </section>

    <section v-else-if="workspaceStore.mode === 'handoff'" class="workspace-card stack">
      <div class="section-header">
        <div>
          <h2 class="section-title">This session needs the full AuthOS client</h2>
          <p class="section-copy">
            Lite only operates against a single organization. This account has access to multiple organizations.
          </p>
        </div>
      </div>
      <BaseButton v-if="workspaceStore.fullClientUrl" @click="openFullClient">
        Continue in full client
      </BaseButton>
      <div v-else class="muted">
        Configure <code>FULL_WEB_CLIENT_BASE_URL</code> to hand multi-organization sessions to the main client.
      </div>
    </section>

    <section v-else-if="workspaceStore.mode === 'no-org'" class="workspace-card stack">
      <h2 class="section-title">No organization is attached yet</h2>
      <p class="section-copy">
        Your account is signed in, but AuthOS Lite cannot load an organization workspace for it yet.
      </p>
    </section>

    <template v-else>
      <div class="workspace-stat-grid">
        <article class="workspace-stat-card">
          <div class="workspace-stat-card__label">Organization status</div>
          <div class="workspace-stat-card__value">
            <span class="status-chip status-chip--success">{{ workspaceStore.currentOrgStatus }}</span>
          </div>
        </article>

        <article class="workspace-stat-card">
          <div class="workspace-stat-card__label">Current role</div>
          <div class="workspace-stat-card__value">{{ authStore.activeOrgRole || 'member' }}</div>
        </article>

        <article class="workspace-stat-card">
          <div class="workspace-stat-card__label">Platform access</div>
          <div class="workspace-stat-card__value">{{ authStore.isPlatformOwner && authStore.isPlatformContext ? 'Platform owner' : 'Organization member' }}</div>
        </article>
      </div>

      <div class="workspace-two-column">
        <section class="workspace-card">
          <div class="section-header">
            <div>
              <h2 class="section-title">Current Session Context</h2>
              <p class="section-copy">The active account, organization, and admin surface attached to this session.</p>
            </div>
          </div>

          <div class="detail-list">
            <div class="detail-list__row">
              <span class="detail-list__label">Active email</span>
              <strong class="detail-list__value">{{ authStore.user?.email || 'Unknown' }}</strong>
            </div>
            <div class="detail-list__row">
              <span class="detail-list__label">Organization role</span>
              <strong class="detail-list__value">{{ authStore.activeOrgRole || 'member' }}</strong>
            </div>
            <div class="detail-list__row">
              <span class="detail-list__label">Active organization</span>
              <strong class="detail-list__value">{{ workspaceStore.currentOrgName }}</strong>
            </div>
            <div class="detail-list__row">
              <span class="detail-list__label">Managed setup</span>
              <strong class="detail-list__value">{{ showSetup ? 'Available' : 'Not available' }}</strong>
            </div>
          </div>
        </section>

        <section class="workspace-card">
          <div class="section-header">
            <div>
              <h2 class="section-title">Support & Troubleshooting</h2>
              <p class="section-copy">Jump straight to the real controls that resolve the most common operator issues.</p>
            </div>
          </div>

          <div class="workspace-action-list">
            <RouterLink to="/app/account-security" class="workspace-action-card">
              <div class="workspace-action-card__title">Review account security</div>
              <div class="workspace-action-card__copy">Reset MFA, review trusted devices, or register passkeys.</div>
            </RouterLink>

            <RouterLink to="/app/applications" class="workspace-action-card">
              <div class="workspace-action-card__title">Update application routing</div>
              <div class="workspace-action-card__copy">Adjust redirect URIs and device activation URLs for the active app.</div>
            </RouterLink>

            <RouterLink to="/app/organization" class="workspace-action-card">
              <div class="workspace-action-card__title">Manage organization access</div>
              <div class="workspace-action-card__copy">Rename the organization or review pending invitations from one place.</div>
            </RouterLink>
          </div>
        </section>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue';
import { RouterLink } from 'vue-router';
import BaseButton from '@/components/BaseButton.vue';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
import { useWorkspaceRuntime } from '@/features/workspace/useWorkspaceRuntime';
import { useAuthStore } from '@/stores/auth';
import { useWorkspaceStore } from '@/stores/workspace';

const authStore = useAuthStore();
const workspaceStore = useWorkspaceStore();
const { reload, openFullClient } = useWorkspaceRuntime();

const showSetup = computed(() => authStore.isPlatformOwner && authStore.isPlatformContext && workspaceStore.managedConfigEnabled);
</script>
