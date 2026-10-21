<template>
  <div class="workspace-layout">
    <button
      v-if="mobileNavOpen"
      type="button"
      class="workspace-sidebar__scrim"
      aria-label="Close navigation"
      @click="closeMobileNav"
    ></button>

    <WorkspaceSidebar
      :show-setup="showSetup"
      :user-email="authStore.userEmail"
      :user-role="authStore.activeOrgRole"
      :full-client-url="workspaceStore.fullClientUrl"
      :mobile-open="mobileNavOpen"
      @logout="handleLogout"
      @open-full-client="openFullClient"
      @close="closeMobileNav"
    />

    <div class="workspace-main">
      <WorkspaceTopbar
        :title="pageTitle"
        :badge-label="badgeLabel"
        :badge-tone="badgeTone"
        :org-label="orgLabel"
        :org-interactive="orgInteractive"
        @refresh="reload"
        @open-full-client="openFullClient"
        @toggle-sidebar="toggleMobileNav"
      />

      <main class="workspace-content">
        <router-view />
      </main>
    </div>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, provide, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import WorkspaceSidebar from '@/features/workspace/components/WorkspaceSidebar.vue';
import WorkspaceTopbar from '@/features/workspace/components/WorkspaceTopbar.vue';
import { useAuthStore } from '@/stores/auth';
import { useWorkspaceStore } from '@/stores/workspace';

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();
const workspaceStore = useWorkspaceStore();

const refreshVersion = ref(0);
const mobileNavOpen = ref(false);

const pageTitle = computed(() => route.meta.workspaceTitle || 'Overview');
const badgeLabel = computed(() => {
  if (workspaceStore.mode === 'ready' && route.name === 'app-overview') {
    return 'Systems Operational';
  }

  if (workspaceStore.mode === 'handoff') {
    return 'Full client required';
  }

  return '';
});
const badgeTone = computed(() => (workspaceStore.mode === 'handoff' ? 'warning' : 'success'));
const showSetup = computed(() => authStore.isPlatformOwner && authStore.isPlatformContext && workspaceStore.managedConfigEnabled);
const orgLabel = computed(() => workspaceStore.currentOrgName || 'AuthOS Lite');
const orgInteractive = computed(() => workspaceStore.mode === 'handoff' && Boolean(workspaceStore.fullClientUrl));

provide('workspaceReload', reload);
provide('workspaceRefreshVersion', refreshVersion);
provide('workspaceOpenFullClient', openFullClient);

watch(
  () => route.fullPath,
  () => {
    closeMobileNav();
  },
);

watch(mobileNavOpen, (open) => {
  document.body.classList.toggle('body-lock', open);
});

onMounted(() => {
  reload();
  window.addEventListener('resize', handleResize);
  window.addEventListener('keydown', handleKeydown);
});

onBeforeUnmount(() => {
  document.body.classList.remove('body-lock');
  window.removeEventListener('resize', handleResize);
  window.removeEventListener('keydown', handleKeydown);
});

async function reload() {
  await workspaceStore.resolveWorkspace();
  refreshVersion.value += 1;
}

function openFullClient() {
  closeMobileNav();
  workspaceStore.redirectToFullClient('/home');
}

async function handleLogout() {
  closeMobileNav();
  await authStore.logout();
  await router.push('/');
}

function toggleMobileNav() {
  mobileNavOpen.value = !mobileNavOpen.value;
}

function closeMobileNav() {
  mobileNavOpen.value = false;
}

function handleResize() {
  if (window.innerWidth >= 1040) {
    closeMobileNav();
  }
}

function handleKeydown(event) {
  if (event.key === 'Escape') {
    closeMobileNav();
  }
}
</script>
