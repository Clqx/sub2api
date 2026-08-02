<template>
  <div v-if="hasHomeContent" class="min-h-screen">
    <iframe
      v-if="customHomeUrl"
      :src="customHomeUrl"
      class="h-screen w-full border-0"
      allowfullscreen
    ></iframe>
    <div v-else v-html="sanitizedHomeContent"></div>
  </div>

  <div
    v-else-if="compactHomeEnabled"
    data-testid="compact-home"
    class="flex min-h-screen flex-col bg-gray-50 text-gray-900 dark:bg-dark-950 dark:text-white"
  >
    <header class="border-b border-gray-200 px-4 py-4 sm:px-6 dark:border-dark-800">
      <nav class="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-3 sm:gap-4">
        <div class="flex min-w-0 flex-1 items-center gap-3">
          <img
            :src="siteLogo || '/logo.svg'"
            alt="Logo"
            class="h-9 w-9 shrink-0 rounded-lg object-contain"
          />
          <span class="min-w-0 truncate text-base font-semibold">{{ siteName }}</span>
        </div>
        <div class="flex max-w-full shrink-0 flex-wrap items-center justify-end gap-2">
          <LocaleSwitcher />
          <a
            v-if="docUrl"
            :href="docUrl"
            target="_blank"
            rel="noopener noreferrer"
            class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg text-gray-500 hover:bg-gray-100 dark:text-dark-400 dark:hover:bg-dark-800"
            :title="t('home.viewDocs')"
          >
            <Icon name="book" size="md" />
          </a>
          <button
            class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg text-gray-500 hover:bg-gray-100 dark:text-dark-400 dark:hover:bg-dark-800"
            :title="isDark ? t('home.switchToLight') : t('home.switchToDark')"
            @click="toggleTheme"
          >
            <Icon :name="isDark ? 'sun' : 'moon'" size="md" />
          </button>
          <router-link
            :to="isAuthenticated ? dashboardPath : '/login'"
            class="inline-flex min-h-10 shrink-0 items-center justify-center rounded-lg bg-gray-900 px-4 py-2 text-sm font-medium text-white hover:bg-gray-800 dark:bg-white dark:text-gray-900 dark:hover:bg-gray-200"
          >
            {{ isAuthenticated ? t('home.dashboard') : t('home.login') }}
          </router-link>
        </div>
      </nav>
    </header>

    <main class="flex min-w-0 flex-1 items-center justify-center px-4 py-16 sm:px-6">
      <div class="min-w-0 max-w-2xl text-center">
        <img
          :src="siteLogo || '/logo.svg'"
          alt="Logo"
          class="mx-auto mb-6 h-20 w-20 rounded-2xl object-contain"
        />
        <h1 class="[overflow-wrap:anywhere] text-3xl font-bold md:text-4xl">{{ siteName }}</h1>
        <p class="mt-4 whitespace-pre-wrap [overflow-wrap:anywhere] text-base text-gray-600 dark:text-dark-300">{{ siteSubtitle }}</p>
        <router-link
          :to="isAuthenticated ? dashboardPath : '/login'"
          class="mt-8 inline-flex min-h-10 items-center justify-center rounded-lg bg-primary-600 px-5 py-2.5 text-sm font-medium text-white hover:bg-primary-700"
        >
          {{ isAuthenticated ? t('home.goToDashboard') : t('home.login') }}
        </router-link>
      </div>
    </main>

    <footer class="min-w-0 border-t border-gray-200 px-4 py-5 text-center text-sm text-gray-500 [overflow-wrap:anywhere] sm:px-6 dark:border-dark-800 dark:text-dark-400">
      &copy; {{ currentYear }} {{ siteName }}
    </footer>
  </div>

  <div v-else class="landing-page">
    <header class="site-header">
      <nav class="site-nav" :aria-label="t('home.nav.primary')">
        <a class="brand" href="#top">
          <img :src="siteLogo || '/logo.svg'" alt="" />
          <span>{{ siteName }}</span>
        </a>
        <div class="nav-links">
          <a href="#products">{{ t('home.nav.products') }}</a>
          <a href="#capabilities">{{ t('home.nav.capabilities') }}</a>
          <a href="#models">{{ t('home.nav.models') }}</a>
        </div>
        <div class="nav-actions">
          <LocaleSwitcher />
          <a
            v-if="docUrl"
            :href="docUrl"
            target="_blank"
            rel="noopener noreferrer"
            class="icon-button"
            :title="t('home.viewDocs')"
          >
            <Icon name="book" size="md" />
          </a>
          <button
            type="button"
            class="icon-button"
            :title="isDark ? t('home.switchToLight') : t('home.switchToDark')"
            @click="toggleTheme"
          >
            <Icon :name="isDark ? 'sun' : 'moon'" size="md" />
          </button>
          <router-link class="header-login" :to="isAuthenticated ? dashboardPath : '/login'">
            <span v-if="isAuthenticated" class="user-initial">{{ userInitial }}</span>
            <Icon v-else name="login" size="sm" />
            {{ isAuthenticated ? t('home.dashboard') : t('home.login') }}
          </router-link>
        </div>
      </nav>
    </header>

    <main id="top">
      <section class="hero" aria-labelledby="hero-title">
        <div class="hero-shade"></div>
        <div class="hero-content">
          <p class="hero-eyebrow">AI API INFRASTRUCTURE</p>
          <h1 id="hero-title">{{ siteName }}</h1>
          <p class="hero-subtitle">{{ siteSubtitle || t('home.heroSubtitle') }}</p>
          <p class="hero-description">{{ t('home.heroDescription') }}</p>
          <div class="hero-actions">
            <router-link class="primary-action" :to="isAuthenticated ? dashboardPath : '/login'">
              {{ isAuthenticated ? t('home.goToDashboard') : t('home.getStarted') }}
              <Icon name="arrowRight" size="sm" />
            </router-link>
            <a class="secondary-action" href="#products">
              {{ t('home.catalog.viewProducts') }}
            </a>
          </div>
        </div>
        <div class="hero-facts" aria-label="Service highlights">
          <div>
            <strong>OpenAI</strong>
            <span>{{ t('home.catalog.unifiedProtocol') }}</span>
          </div>
          <div>
            <strong>Claude · GPT · Gemini</strong>
            <span>{{ t('home.catalog.modelCoverage') }}</span>
          </div>
          <div>
            <strong>24 / 7</strong>
            <span>{{ t('home.catalog.serviceAvailability') }}</span>
          </div>
        </div>
      </section>

      <section id="products" class="catalog-section section-band" aria-labelledby="catalog-title">
        <div class="section-inner">
          <div class="section-heading">
            <div>
              <p class="section-eyebrow">PRODUCT CATALOG</p>
              <h2 id="catalog-title">{{ t('home.catalog.title') }}</h2>
            </div>
            <p>{{ t('home.catalog.description') }}</p>
          </div>

          <div v-if="catalogLoading" class="catalog-state" aria-live="polite">
            <span class="loading-line"></span>
            <span class="loading-line"></span>
            <span class="loading-line"></span>
          </div>
          <div v-else-if="catalogUnavailable" class="catalog-message" role="status">
            <Icon name="exclamationCircle" size="md" />
            <div>
              <strong>{{ t('home.catalog.unavailable') }}</strong>
              <p>{{ t('home.catalog.unavailableDescription') }}</p>
            </div>
          </div>
          <div v-else-if="products.length === 0" class="catalog-message" role="status">
            <Icon name="cube" size="md" />
            <div>
              <strong>{{ t('home.catalog.empty') }}</strong>
              <p>{{ t('home.catalog.emptyDescription') }}</p>
            </div>
          </div>
          <div v-else class="product-grid">
            <article v-for="product in products" :key="product.id" class="product-card">
              <div class="product-heading">
                <span class="product-icon" aria-hidden="true">
                  <span>{{ product.name.charAt(0).toUpperCase() }}</span>
                  <img
                    v-if="productIcon(product)"
                    :src="productIcon(product)"
                    alt=""
                    loading="lazy"
                    @error="hideBrokenIcon"
                  />
                </span>
                <span class="product-sku">{{ product.sku }}</span>
              </div>
              <div class="product-copy">
                <h3>{{ product.name }}</h3>
                <p>{{ product.description || t('home.catalog.defaultDescription') }}</p>
              </div>
              <div class="product-benefit">
                <Icon :name="product.benefit_type === 'subscription' ? 'calendar' : 'creditCard'" size="sm" />
                {{ benefitText(product) }}
              </div>
              <div class="product-footer">
                <strong class="product-price">{{ formatPrice(product) }}</strong>
                <a
                  v-if="purchaseUrl(product)"
                  class="buy-button"
                  :href="purchaseUrl(product)"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {{ t('home.catalog.buy') }}
                  <Icon name="externalLink" size="xs" />
                </a>
                <button v-else class="buy-button disabled" type="button" disabled>
                  {{ t('home.catalog.comingSoon') }}
                </button>
              </div>
            </article>
          </div>

          <div v-if="redeemURL" class="catalog-redeem">
            <div>
              <Icon name="gift" size="lg" />
              <span>
                <strong>{{ t('home.catalog.haveCode') }}</strong>
                <small>{{ t('home.catalog.haveCodeDescription') }}</small>
              </span>
            </div>
            <a :href="redeemURL" class="redeem-link">
              {{ t('home.catalog.redeemNow') }}
              <Icon name="arrowRight" size="sm" />
            </a>
          </div>
        </div>
      </section>

      <section id="capabilities" class="capability-section section-band" aria-labelledby="capability-title">
        <div class="section-inner">
          <div class="section-heading">
            <div>
              <p class="section-eyebrow">BUILT FOR RELIABLE ACCESS</p>
              <h2 id="capability-title">{{ t('home.capabilities.title') }}</h2>
            </div>
            <p>{{ t('home.capabilities.description') }}</p>
          </div>
          <div class="capability-grid">
            <article>
              <Icon name="server" size="lg" />
              <h3>{{ t('home.features.unifiedGateway') }}</h3>
              <p>{{ t('home.features.unifiedGatewayDesc') }}</p>
            </article>
            <article>
              <Icon name="users" size="lg" />
              <h3>{{ t('home.features.multiAccount') }}</h3>
              <p>{{ t('home.features.multiAccountDesc') }}</p>
            </article>
            <article>
              <Icon name="chartBar" size="lg" />
              <h3>{{ t('home.features.balanceQuota') }}</h3>
              <p>{{ t('home.features.balanceQuotaDesc') }}</p>
            </article>
          </div>
        </div>
      </section>

      <section id="models" class="model-section section-band" aria-labelledby="model-title">
        <div class="section-inner model-layout">
          <div>
            <p class="section-eyebrow">MODEL ROUTING</p>
            <h2 id="model-title">{{ t('home.providers.title') }}</h2>
            <p>{{ t('home.providers.description') }}</p>
          </div>
          <div class="model-list">
            <span><b>C</b> Claude</span>
            <span><b>G</b> GPT</span>
            <span><b>G</b> {{ t('home.providers.gemini') }}</span>
            <span><b>A</b> {{ t('home.providers.antigravity') }}</span>
          </div>
        </div>
      </section>

      <section class="closing-section section-band">
        <div class="section-inner closing-layout">
          <div>
            <p class="section-eyebrow">START BUILDING</p>
            <h2>{{ t('home.cta.title') }}</h2>
            <p>{{ t('home.cta.description') }}</p>
          </div>
          <router-link class="primary-action light" :to="isAuthenticated ? dashboardPath : '/login'">
            {{ isAuthenticated ? t('home.goToDashboard') : t('home.cta.button') }}
            <Icon name="arrowRight" size="sm" />
          </router-link>
        </div>
      </section>
    </main>

    <footer class="site-footer">
      <div>
        <span>&copy; {{ currentYear }} {{ siteName }}. {{ t('home.footer.allRightsReserved') }}</span>
        <nav>
          <a v-if="docUrl" :href="docUrl" target="_blank" rel="noopener noreferrer">{{ t('home.docs') }}</a>
          <a :href="githubUrl" target="_blank" rel="noopener noreferrer">GitHub</a>
        </nav>
      </div>
    </footer>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import DOMPurify from 'dompurify'
import { useAuthStore, useAppStore } from '@/stores'
import LocaleSwitcher from '@/components/common/LocaleSwitcher.vue'
import Icon from '@/components/icons/Icon.vue'
import { sanitizeUrl } from '@/utils/url'

interface CatalogProduct {
  id: string
  sku: string
  name: string
  description: string
  price: string
  currency: string
  benefit_type: 'balance' | 'subscription'
  value: string
  group_id: number | null
  validity_days: number | null
  purchase_url: string
  icon_url: string
}

interface CatalogResponse {
  code: number
  data: CatalogProduct[]
}

const { t, locale } = useI18n()
const authStore = useAuthStore()
const appStore = useAppStore()

const siteName = computed(() => appStore.cachedPublicSettings?.site_name || appStore.siteName || 'Sub2API')
const siteLogo = computed(() => sanitizeUrl(appStore.cachedPublicSettings?.site_logo || appStore.siteLogo || '', { allowRelative: true, allowDataUrl: true }))
const siteSubtitle = computed(() => appStore.cachedPublicSettings?.site_subtitle || t('home.heroSubtitle'))
const docUrl = computed(() => sanitizeUrl(appStore.cachedPublicSettings?.doc_url || appStore.docUrl || ''))
const homeContent = computed(() => appStore.cachedPublicSettings?.home_content || '')
const hasHomeContent = computed(() => homeContent.value.trim().length > 0)
const customHomeUrl = computed(() => sanitizeUrl(homeContent.value))
const sanitizedHomeContent = computed(() => DOMPurify.sanitize(homeContent.value))
const compactHomeEnabled = computed(() => appStore.cachedPublicSettings?.compact_home_enabled === true)

const redeemMenu = computed(() => (appStore.cachedPublicSettings?.custom_menu_items ?? [])
  .find((item) => item.id === 'redeem-center' && item.visibility === 'user'))
const redeemURL = computed(() => sanitizeUrl(redeemMenu.value?.url || ''))
const catalogEndpoint = computed(() => {
  if (!redeemURL.value) return ''
  try {
    const url = new URL(redeemURL.value, window.location.origin)
    return new URL('/api/public/products', url.origin).toString()
  } catch {
    return ''
  }
})

const products = ref<CatalogProduct[]>([])
const catalogLoading = ref(true)
const catalogUnavailable = ref(false)
const isDark = ref(document.documentElement.classList.contains('dark'))
const isAuthenticated = computed(() => authStore.isAuthenticated)
const dashboardPath = computed(() => authStore.isAdmin ? '/admin/dashboard' : '/dashboard')
const userInitial = computed(() => authStore.user?.email?.charAt(0).toUpperCase() || 'U')
const currentYear = new Date().getFullYear()
const githubUrl = 'https://github.com/Wei-Shaw/sub2api'

function toggleTheme() {
  isDark.value = !isDark.value
  document.documentElement.classList.toggle('dark', isDark.value)
  localStorage.setItem('theme', isDark.value ? 'dark' : 'light')
}

function initTheme() {
  const savedTheme = localStorage.getItem('theme')
  if (savedTheme === 'dark' || (!savedTheme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    isDark.value = true
    document.documentElement.classList.add('dark')
  }
}

function productIcon(product: CatalogProduct) {
  return sanitizeUrl(product.icon_url || '')
}

function purchaseUrl(product: CatalogProduct) {
  return sanitizeUrl(product.purchase_url || '')
}

function hideBrokenIcon(event: Event) {
  const image = event.currentTarget as HTMLImageElement
  image.remove()
}

function formatPrice(product: CatalogProduct) {
  try {
    return new Intl.NumberFormat(locale.value, {
      style: 'currency',
      currency: product.currency,
      maximumFractionDigits: 6,
    }).format(Number(product.price))
  } catch {
    return `${product.currency} ${product.price}`
  }
}

function benefitText(product: CatalogProduct) {
  if (product.benefit_type === 'subscription') {
    return t('home.catalog.subscriptionBenefit', { days: product.validity_days || 0 })
  }
  return t('home.catalog.balanceBenefit', { value: product.value })
}

async function loadCatalog() {
  catalogLoading.value = true
  catalogUnavailable.value = false
  if (!catalogEndpoint.value) {
    catalogUnavailable.value = true
    catalogLoading.value = false
    return
  }
  try {
    const response = await fetch(catalogEndpoint.value, { headers: { Accept: 'application/json' } })
    if (!response.ok) throw new Error(`catalog request failed: ${response.status}`)
    const body = await response.json() as CatalogResponse
    products.value = Array.isArray(body.data) ? body.data : []
  } catch {
    catalogUnavailable.value = true
  } finally {
    catalogLoading.value = false
  }
}

onMounted(async () => {
  initTheme()
  await Promise.all([
    authStore.checkAuth(),
    appStore.publicSettingsLoaded ? Promise.resolve() : appStore.fetchPublicSettings(),
  ])
  await loadCatalog()
})
</script>

<style scoped>
.landing-page {
  --page: #f5f7f6;
  --surface: #ffffff;
  --ink: #15201d;
  --muted: #63706c;
  --line: #dce3e0;
  --brand: #087c6b;
  --brand-dark: #056355;
  min-width: 320px;
  min-height: 100vh;
  color: var(--ink);
  background: var(--page);
  letter-spacing: 0;
}

:global(.dark) .landing-page {
  --page: #101513;
  --surface: #171d1b;
  --ink: #f1f5f3;
  --muted: #a6b1ad;
  --line: #303a36;
  --brand: #35b49d;
  --brand-dark: #72d6c3;
}

.site-header {
  position: sticky;
  z-index: 30;
  top: 0;
  border-bottom: 1px solid var(--line);
  background: color-mix(in srgb, var(--surface) 94%, transparent);
  backdrop-filter: blur(14px);
}

.site-nav,
.section-inner,
.site-footer > div {
  width: min(1180px, calc(100% - 48px));
  margin: 0 auto;
}

.site-nav {
  display: flex;
  min-height: 68px;
  align-items: center;
  justify-content: space-between;
  gap: 28px;
}

.brand,
.nav-actions,
.header-login,
.primary-action,
.secondary-action,
.buy-button,
.redeem-link,
.catalog-redeem > div,
.product-benefit {
  display: inline-flex;
  align-items: center;
}

.brand {
  min-width: 0;
  gap: 10px;
  color: var(--ink);
  font-size: 16px;
  font-weight: 750;
}

.brand img {
  width: 34px;
  height: 34px;
  object-fit: contain;
}

.brand span {
  overflow: hidden;
  max-width: 220px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.nav-links {
  display: flex;
  flex: 1;
  justify-content: center;
  gap: 34px;
}

.nav-links a,
.site-footer a {
  color: var(--muted);
  font-size: 13px;
  font-weight: 600;
  transition: color 150ms ease;
}

.nav-links a:hover,
.site-footer a:hover {
  color: var(--brand);
}

.nav-actions {
  gap: 8px;
}

.icon-button {
  display: grid;
  width: 36px;
  height: 36px;
  place-items: center;
  border: 0;
  border-radius: 6px;
  color: var(--muted);
  background: transparent;
}

.icon-button:hover {
  color: var(--ink);
  background: var(--page);
}

.header-login {
  min-height: 38px;
  gap: 7px;
  padding: 0 14px;
  border-radius: 6px;
  color: #ffffff;
  background: #17221f;
  font-size: 13px;
  font-weight: 700;
}

.user-initial {
  display: grid;
  width: 20px;
  height: 20px;
  place-items: center;
  border-radius: 50%;
  color: #053b33;
  background: #80ddca;
  font-size: 10px;
}

.hero {
  position: relative;
  display: flex;
  min-height: min(690px, calc(100vh - 68px));
  flex-direction: column;
  justify-content: space-between;
  overflow: hidden;
  color: #ffffff;
  background-color: #10231f;
  background-image: url('/product-console.jpg');
  background-position: center 28%;
  background-size: cover;
}

.hero-shade {
  position: absolute;
  inset: 0;
  background: rgb(6 20 17 / 72%);
}

.hero-content {
  position: relative;
  z-index: 1;
  width: min(1180px, calc(100% - 48px));
  margin: auto;
  padding: 90px 0 74px;
}

.hero-eyebrow,
.section-eyebrow {
  margin: 0 0 16px;
  color: #60d1ba;
  font-size: 11px;
  font-weight: 750;
}

.hero h1 {
  max-width: 820px;
  margin: 0;
  overflow-wrap: anywhere;
  font-size: 64px;
  line-height: 1.06;
}

.hero-subtitle {
  max-width: 700px;
  margin: 24px 0 0;
  font-size: 25px;
  font-weight: 650;
  line-height: 1.4;
}

.hero-description {
  max-width: 650px;
  margin: 14px 0 0;
  color: #d3ddda;
  font-size: 16px;
  line-height: 1.75;
}

.hero-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 34px;
}

.primary-action,
.secondary-action,
.buy-button,
.redeem-link {
  justify-content: center;
  gap: 9px;
  min-height: 46px;
  padding: 0 20px;
  border: 1px solid transparent;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 700;
}

.primary-action {
  color: #073b32;
  background: #71dbc6;
}

.secondary-action {
  border-color: rgb(255 255 255 / 55%);
  color: #ffffff;
  background: rgb(9 26 22 / 42%);
}

.hero-facts {
  position: relative;
  z-index: 1;
  display: grid;
  width: min(1180px, calc(100% - 48px));
  grid-template-columns: repeat(3, 1fr);
  margin: 0 auto;
  border-top: 1px solid rgb(255 255 255 / 28%);
}

.hero-facts div {
  min-width: 0;
  padding: 24px 30px;
  border-left: 1px solid rgb(255 255 255 / 20%);
}

.hero-facts div:first-child {
  padding-left: 0;
  border-left: 0;
}

.hero-facts strong,
.hero-facts span {
  display: block;
}

.hero-facts strong {
  overflow-wrap: anywhere;
  font-size: 14px;
}

.hero-facts span {
  margin-top: 5px;
  color: #b9c9c4;
  font-size: 11px;
}

.section-band {
  scroll-margin-top: 68px;
  border-bottom: 1px solid var(--line);
}

.catalog-section {
  padding: 90px 0;
  background: var(--surface);
}

.section-heading {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(280px, 460px);
  align-items: end;
  gap: 60px;
  margin-bottom: 40px;
}

.section-heading h2,
.model-layout h2,
.closing-layout h2 {
  margin: 0;
  font-size: 36px;
  line-height: 1.2;
}

.section-heading > p,
.model-layout > div > p:last-child,
.closing-layout p {
  margin: 0;
  color: var(--muted);
  font-size: 15px;
  line-height: 1.75;
}

.section-eyebrow {
  color: var(--brand);
}

.product-grid,
.catalog-state {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
}

.product-card {
  display: grid;
  min-width: 0;
  min-height: 342px;
  grid-template-rows: auto 1fr auto auto;
  gap: 20px;
  padding: 24px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface);
  transition: border-color 150ms ease, box-shadow 150ms ease;
}

.product-card:hover {
  border-color: color-mix(in srgb, var(--brand) 50%, var(--line));
  box-shadow: 0 12px 30px rgb(28 59 50 / 8%);
}

.product-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.product-icon {
  position: relative;
  display: grid;
  width: 52px;
  height: 52px;
  flex: 0 0 52px;
  overflow: hidden;
  place-items: center;
  border: 1px solid color-mix(in srgb, var(--brand) 22%, var(--line));
  border-radius: 7px;
  color: var(--brand-dark);
  background: color-mix(in srgb, var(--brand) 10%, var(--surface));
  font-size: 18px;
  font-weight: 800;
}

.product-icon img {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  background: var(--surface);
  object-fit: cover;
}

.product-sku {
  overflow: hidden;
  color: var(--muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.product-copy h3 {
  overflow-wrap: anywhere;
  margin: 0;
  font-size: 19px;
  line-height: 1.4;
}

.product-copy p {
  margin: 10px 0 0;
  color: var(--muted);
  font-size: 13px;
  line-height: 1.7;
  white-space: pre-line;
}

.product-benefit {
  gap: 8px;
  color: var(--brand-dark);
  font-size: 12px;
  font-weight: 700;
}

.product-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding-top: 18px;
  border-top: 1px solid var(--line);
}

.product-price {
  overflow-wrap: anywhere;
  font-size: 22px;
  line-height: 1.2;
}

.buy-button {
  min-height: 38px;
  padding: 0 13px;
  color: #ffffff;
  background: #17221f;
  font-size: 12px;
}

.buy-button.disabled {
  color: var(--muted);
  background: var(--page);
}

.catalog-state .loading-line {
  height: 342px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: color-mix(in srgb, var(--page) 75%, var(--surface));
  animation: loading-pulse 1.4s ease-in-out infinite alternate;
}

@keyframes loading-pulse {
  to { opacity: 0.52; }
}

.catalog-message {
  display: flex;
  min-height: 130px;
  align-items: center;
  gap: 16px;
  padding: 26px;
  border: 1px solid var(--line);
  color: var(--muted);
  background: var(--page);
}

.catalog-message strong {
  display: block;
  color: var(--ink);
  font-size: 15px;
}

.catalog-message p {
  margin: 5px 0 0;
  font-size: 13px;
}

.catalog-redeem {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 28px;
  margin-top: 20px;
  padding: 22px 24px;
  border: 1px solid #cfe4dd;
  background: color-mix(in srgb, var(--brand) 7%, var(--surface));
}

.catalog-redeem > div {
  gap: 14px;
  color: var(--brand-dark);
}

.catalog-redeem span,
.catalog-redeem strong,
.catalog-redeem small {
  display: block;
}

.catalog-redeem small {
  margin-top: 4px;
  color: var(--muted);
  font-size: 12px;
}

.redeem-link {
  flex: 0 0 auto;
  min-height: 40px;
  color: #ffffff;
  background: var(--brand-dark);
  font-size: 12px;
}

.capability-section {
  padding: 90px 0;
  background: var(--page);
}

.capability-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  border-top: 1px solid var(--line);
  border-bottom: 1px solid var(--line);
}

.capability-grid article {
  min-width: 0;
  padding: 34px 36px;
  border-left: 1px solid var(--line);
}

.capability-grid article:first-child {
  padding-left: 0;
  border-left: 0;
}

.capability-grid svg {
  color: var(--brand);
}

.capability-grid h3 {
  margin: 22px 0 10px;
  font-size: 17px;
}

.capability-grid p {
  margin: 0;
  color: var(--muted);
  font-size: 13px;
  line-height: 1.75;
}

.model-section {
  padding: 76px 0;
  background: var(--surface);
}

.model-layout {
  display: grid;
  grid-template-columns: minmax(280px, 0.8fr) minmax(0, 1.2fr);
  align-items: center;
  gap: 80px;
}

.model-layout > div > p:last-child {
  margin-top: 18px;
}

.model-list {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  border-top: 1px solid var(--line);
  border-left: 1px solid var(--line);
}

.model-list span {
  display: flex;
  min-height: 82px;
  align-items: center;
  gap: 14px;
  padding: 18px;
  border-right: 1px solid var(--line);
  border-bottom: 1px solid var(--line);
  font-size: 14px;
  font-weight: 700;
}

.model-list b {
  display: grid;
  width: 34px;
  height: 34px;
  place-items: center;
  border-radius: 6px;
  color: var(--brand-dark);
  background: color-mix(in srgb, var(--brand) 10%, var(--surface));
}

.closing-section {
  padding: 68px 0;
  color: #ffffff;
  background: #14231f;
}

.closing-layout {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 48px;
}

.closing-layout p {
  margin-top: 12px;
  color: #b8c7c2;
}

.primary-action.light {
  flex: 0 0 auto;
  background: #ffffff;
}

.site-footer {
  padding: 28px 0;
  color: var(--muted);
  background: var(--surface);
  font-size: 12px;
}

.site-footer > div,
.site-footer nav {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 22px;
}

.site-footer nav {
  justify-content: flex-end;
}

@media (max-width: 900px) {
  .nav-links { display: none; }
  .hero h1 { font-size: 50px; }
  .product-grid,
  .catalog-state { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .catalog-state .loading-line:last-child { display: none; }
  .section-heading { grid-template-columns: 1fr; gap: 18px; }
  .model-layout { gap: 44px; }
}

@media (max-width: 680px) {
  .site-nav,
  .section-inner,
  .site-footer > div,
  .hero-content,
  .hero-facts { width: min(100% - 32px, 1180px); }
  .site-nav { min-height: 62px; gap: 12px; }
  .brand span { max-width: 120px; font-size: 14px; }
  .brand img { width: 30px; height: 30px; }
  .nav-actions { gap: 3px; }
  .nav-actions > :deep(.locale-switcher) { display: none; }
  .icon-button { width: 32px; height: 34px; }
  .header-login { min-height: 36px; padding: 0 10px; font-size: 12px; }
  .hero { min-height: 650px; background-position: 62% center; }
  .hero-content { padding: 74px 0 48px; }
  .hero h1 { font-size: 40px; }
  .hero-subtitle { font-size: 20px; }
  .hero-description { font-size: 14px; }
  .hero-facts { grid-template-columns: 1fr; }
  .hero-facts div { padding: 14px 0; border-top: 1px solid rgb(255 255 255 / 16%); border-left: 0; }
  .hero-facts div:first-child { border-top: 0; }
  .catalog-section,
  .capability-section { padding: 66px 0; }
  .section-heading h2,
  .model-layout h2,
  .closing-layout h2 { font-size: 29px; }
  .product-grid,
  .catalog-state { grid-template-columns: 1fr; }
  .catalog-state .loading-line:nth-child(n + 2) { display: none; }
  .product-card { min-height: 320px; }
  .catalog-redeem,
  .closing-layout { align-items: flex-start; flex-direction: column; }
  .catalog-redeem { padding: 20px; }
  .redeem-link { width: 100%; }
  .capability-grid { grid-template-columns: 1fr; }
  .capability-grid article,
  .capability-grid article:first-child { padding: 28px 0; border-top: 1px solid var(--line); border-left: 0; }
  .capability-grid article:first-child { border-top: 0; }
  .model-section { padding: 64px 0; }
  .model-layout { grid-template-columns: 1fr; }
  .model-list { grid-template-columns: 1fr; }
  .closing-section { padding: 58px 0; }
  .primary-action.light { width: 100%; }
  .site-footer > div { align-items: flex-start; flex-direction: column; }
}

@media (max-width: 390px) {
  .brand span { display: none; }
  .hero-actions > * { width: 100%; }
  .product-footer { align-items: flex-start; flex-direction: column; }
  .buy-button { width: 100%; }
}

@media (prefers-reduced-motion: reduce) {
  .catalog-state .loading-line { animation: none; }
}
</style>
