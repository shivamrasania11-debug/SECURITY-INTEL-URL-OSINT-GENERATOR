/**
 * Security Analysis & URL Intelligence Generator - Main Frontend Logic (main.js)
 * Manages API communication, reactive UI state, animations, tabs, exports, and toasts.
 */

(function () {
  'use strict';

  // Global State Storage
  window.currentDorksData = null;
  window.currentAnalysisData = null;

  // DOM Elements Cache
  const elements = {
    // Theme & Nav
    themeToggleBtn: document.getElementById('themeToggleBtn'),
    mobileMenuBtn: document.getElementById('mobileMenuBtn'),
    navMenu: document.getElementById('navMenu'),
    liveUtcClock: document.getElementById('liveUtcClock'),

    // Ethical Modal
    ethicsModal: document.getElementById('ethicsModal'),
    acknowledgeEthicsBtn: document.getElementById('acknowledgeEthicsBtn'),

    // OSINT Generator Form & Inputs
    dorkForm: document.getElementById('dorkForm'),
    dorkDomain: document.getElementById('dorkDomain'),
    clearDorkDomain: document.getElementById('clearDorkDomain'),
    generateDorksBtn: document.getElementById('generateDorksBtn'),
    dorkAuthorized: document.getElementById('dorkAuthorized'),
    selectAllCategoriesBtn: document.getElementById('selectAllCategoriesBtn'),
    clearAllCategoriesBtn: document.getElementById('clearAllCategoriesBtn'),

    // OSINT Results
    dorkResultsContainer: document.getElementById('dorkResultsContainer'),
    dorkResultsCountBadge: document.getElementById('dorkResultsCountBadge'),
    dorkTargetDomainBadge: document.getElementById('dorkTargetDomainBadge'),
    dorkCategoryFilters: document.getElementById('dorkCategoryFilters'),
    dorkCardsGrid: document.getElementById('dorkCardsGrid'),
    copyAllDorksBtn: document.getElementById('copyAllDorksBtn'),
    exportDorksDropdownBtn: document.getElementById('exportDorksDropdownBtn'),
    dorksExportMenu: document.getElementById('dorksExportMenu'),

    // URL Analyzer Form & Inputs
    analyzerForm: document.getElementById('analyzerForm'),
    analyzerUrl: document.getElementById('analyzerUrl'),
    clearAnalyzerUrl: document.getElementById('clearAnalyzerUrl'),
    analyzerAuthorized: document.getElementById('analyzerAuthorized'),
    analyzeUrlBtn: document.getElementById('analyzeUrlBtn'),

    // Scanner Overlay
    scannerOverlay: document.getElementById('scannerOverlay'),
    scannerProgressText: document.getElementById('scannerProgressText'),

    // URL Analyzer Results
    analyzerResultsContainer: document.getElementById('analyzerResultsContainer'),
    riskGaugeMeter: document.getElementById('riskGaugeMeter'),
    riskScoreValue: document.getElementById('riskScoreValue'),
    riskLevelBadge: document.getElementById('riskLevelBadge'),
    riskTargetUrl: document.getElementById('riskTargetUrl'),
    riskNarrativeText: document.getElementById('riskNarrativeText'),
    metricRiskPercentage: document.getElementById('metricRiskPercentage'),
    metricIp: document.getElementById('metricIp'),
    metricSafety: document.getElementById('metricSafety'),
    metricScheme: document.getElementById('metricScheme'),
    metricTld: document.getElementById('metricTld'),
    metricLength: document.getElementById('metricLength'),
    metricSsl: document.getElementById('metricSsl'),
    metricHops: document.getElementById('metricHops'),
    metricFlags: document.getElementById('metricFlags'),
    copyAnalysisSummaryBtn: document.getElementById('copyAnalysisSummaryBtn'),
    exportAnalysisDropdownBtn: document.getElementById('exportAnalysisDropdownBtn'),
    analysisExportMenu: document.getElementById('analysisExportMenu'),
    flagsTabCount: document.getElementById('flagsTabCount'),
    analysisTabPanels: document.getElementById('analysisTabPanels'),

    // Tab Panels & Bodies
    structureTableBody: document.getElementById('structureTableBody'),
    queryParamsListContainer: document.getElementById('queryParamsListContainer'),
    queryParamCountLabel: document.getElementById('queryParamCountLabel'),
    primaryIpDisplay: document.getElementById('primaryIpDisplay'),
    dnsDomainValue: document.getElementById('dnsDomainValue'),
    dnsHostValue: document.getElementById('dnsHostValue'),
    dnsIpv4Tags: document.getElementById('dnsIpv4Tags'),
    dnsIpv6Tags: document.getElementById('dnsIpv6Tags'),
    dnsPtrValue: document.getElementById('dnsPtrValue'),
    whoisRegistrar: document.getElementById('whoisRegistrar'),
    whoisAge: document.getElementById('whoisAge'),
    whoisCreated: document.getElementById('whoisCreated'),
    whoisExpires: document.getElementById('whoisExpires'),
    sslStatusNotice: document.getElementById('sslStatusNotice'),
    sslIssuer: document.getElementById('sslIssuer'),
    sslSubject: document.getElementById('sslSubject'),
    sslValidFrom: document.getElementById('sslValidFrom'),
    sslValidTo: document.getElementById('sslValidTo'),
    sslDaysRemaining: document.getElementById('sslDaysRemaining'),
    sslSelfSigned: document.getElementById('sslSelfSigned'),
    sslSanTags: document.getElementById('sslSanTags'),
    redirectHopCountBadge: document.getElementById('redirectHopCountBadge'),
    redirectDowngradeBadge: document.getElementById('redirectDowngradeBadge'),
    redirectCrossDomainBadge: document.getElementById('redirectCrossDomainBadge'),
    redirectTimelineContainer: document.getElementById('redirectTimelineContainer'),
    flagsGridContainer: document.getElementById('flagsGridContainer'),

    // Toasts
    toastStack: document.getElementById('toastStack')
  };

  /* ==========================================================================
     1. Initialization & LifeCycle
     ========================================================================== */
  document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initEthicsModal();
    initLiveClock();
    initMobileNav();
    initQuickPicks();
    initCategoryChips();
    initSearchEngineRadios();
    initEventListeners();
    initTilt();
    animateStatsCounters();
    restorePreviousInputs();
    initPdfExport();
    initModernHelpCenter();
    initContactForm();
    initKeyboardShortcuts();
  });

  /* ==========================================================================
     2. Theme & UI Helpers
     ========================================================================== */
  function initTheme() {
    const savedTheme = localStorage.getItem('security_intel_theme') || 'dark';
    applyTheme(savedTheme);

    elements.themeToggleBtn.addEventListener('click', () => {
      const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      applyTheme(newTheme);
      showToast(`Switched to ${newTheme} mode`, 'info');
    });
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    document.body.className = `theme-${theme}`;
    localStorage.setItem('security_intel_theme', theme);

    if (window.updateThreeTheme) {
      window.updateThreeTheme(theme);
    }
  }

  function initEthicsModal() {
    const accepted = localStorage.getItem('security_intel_ethics_accepted');
    const modal = elements.ethicsModal || document.getElementById('ethicsModal');
    const ackBtn = elements.acknowledgeEthicsBtn || document.getElementById('acknowledgeEthicsBtn');
    const closeBtn = document.getElementById('closeEthicsModalBtn');

    function dismissEthicsModal() {
      localStorage.setItem('security_intel_ethics_accepted', 'true');
      if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('show');
        modal.style.display = 'none';
      }
      document.body.style.overflow = '';
      showToast('Authorized research terms acknowledged.', 'success');
    }

    if (!accepted && modal) {
      modal.classList.remove('hidden');
      modal.classList.add('show');
      modal.style.display = 'flex';
      document.body.style.overflow = 'hidden';
    } else if (modal) {
      modal.classList.add('hidden');
      modal.classList.remove('show');
      modal.style.display = 'none';
      document.body.style.overflow = '';
    }

    if (ackBtn) {
      ackBtn.addEventListener('click', dismissEthicsModal);
    }
    if (closeBtn) {
      closeBtn.addEventListener('click', dismissEthicsModal);
    }
    if (modal) {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) dismissEthicsModal();
      });
    }
  }

  function initLiveClock() {
    function updateClock() {
      const now = new Date();
      try {
        const timeStr = new Intl.DateTimeFormat('en-IN', {
          timeZone: 'Asia/Kolkata',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: false
        }).format(now);
        if (elements.liveUtcClock) {
          elements.liveUtcClock.textContent = `${timeStr} IST (Kolkata)`;
        }
      } catch (err) {
        // Fallback offset calculation (UTC + 5:30)
        const utcMs = now.getTime() + (now.getTimezoneOffset() * 60000);
        const kolkataDate = new Date(utcMs + (5.5 * 3600000));
        const h = String(kolkataDate.getHours()).padStart(2, '0');
        const m = String(kolkataDate.getMinutes()).padStart(2, '0');
        const s = String(kolkataDate.getSeconds()).padStart(2, '0');
        if (elements.liveUtcClock) {
          elements.liveUtcClock.textContent = `${h}:${m}:${s} IST (Kolkata)`;
        }
      }
    }
    updateClock();
    setInterval(updateClock, 1000);
  }

  function initMobileNav() {
    if (!elements.mobileMenuBtn || !elements.navMenu) return;
    elements.mobileMenuBtn.addEventListener('click', () => {
      const isVisible = elements.navMenu.style.display === 'flex';
      elements.navMenu.style.display = isVisible ? 'none' : 'flex';
      elements.navMenu.style.flexDirection = 'column';
      elements.navMenu.style.position = 'absolute';
      elements.navMenu.style.top = '72px';
      elements.navMenu.style.left = '0';
      elements.navMenu.style.width = '100%';
      elements.navMenu.style.background = 'var(--bg-card)';
      elements.navMenu.style.padding = '1.5rem';
    });
  }

  function initTilt() {
    if (typeof VanillaTilt !== 'undefined') {
      VanillaTilt.init(document.querySelectorAll('[data-tilt]'), {
        max: 8,
        speed: 400,
        glare: true,
        'max-glare': 0.15
      });
    }
  }

  function animateStatsCounters() {
    const statNumbers = document.querySelectorAll('.stat-number[data-target]');
    statNumbers.forEach(el => {
      const target = parseInt(el.getAttribute('data-target'), 10);
      if (isNaN(target)) return;

      let count = 0;
      const step = Math.max(1, Math.floor(target / 20));
      const interval = setInterval(() => {
        count += step;
        if (count >= target) {
          el.textContent = `${target}+`;
          clearInterval(interval);
        } else {
          el.textContent = count;
        }
      }, 40);
    });
  }

  function restorePreviousInputs() {
    const lastDomain = localStorage.getItem('last_dork_domain');
    const lastUrl = localStorage.getItem('last_analyzer_url');
    if (lastDomain && elements.dorkDomain) elements.dorkDomain.value = lastDomain;
    if (lastUrl && elements.analyzerUrl) elements.analyzerUrl.value = lastUrl;
  }

  /* ==========================================================================
     3. Category Chips & Quick Picks
     ========================================================================== */
  function initQuickPicks() {
    // OSINT Quick domain chips
    document.querySelectorAll('.quick-chip[data-domain]').forEach(btn => {
      btn.addEventListener('click', () => {
        elements.dorkDomain.value = btn.getAttribute('data-domain');
        elements.dorkDomain.focus();
      });
    });

    if (elements.clearDorkDomain) {
      elements.clearDorkDomain.addEventListener('click', () => {
        elements.dorkDomain.value = '';
        elements.dorkDomain.focus();
      });
    }

    // URL Analyzer Test Scenario buttons
    document.querySelectorAll('.test-scenario-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        elements.analyzerUrl.value = btn.getAttribute('data-url');
        elements.analyzerUrl.focus();
      });
    });

    if (elements.clearAnalyzerUrl) {
      elements.clearAnalyzerUrl.addEventListener('click', () => {
        elements.analyzerUrl.value = '';
        elements.analyzerUrl.focus();
      });
    }
  }

  function initCategoryChips() {
    const chips = document.querySelectorAll('.category-chip');
    chips.forEach(chip => {
      const checkbox = chip.querySelector('input[type="checkbox"]');
      chip.addEventListener('click', (e) => {
        // Prevent double trigger if clicking label/inner directly
        if (e.target.tagName !== 'INPUT') {
          checkbox.checked = !checkbox.checked;
        }
        chip.classList.toggle('active', checkbox.checked);
      });
    });

    if (elements.selectAllCategoriesBtn) {
      elements.selectAllCategoriesBtn.addEventListener('click', () => {
        chips.forEach(chip => {
          chip.classList.add('active');
          chip.querySelector('input[type="checkbox"]').checked = true;
        });
      });
    }

    if (elements.clearAllCategoriesBtn) {
      elements.clearAllCategoriesBtn.addEventListener('click', () => {
        chips.forEach(chip => {
          chip.classList.remove('active');
          chip.querySelector('input[type="checkbox"]').checked = false;
        });
      });
    }
  }

  function initSearchEngineRadios() {
    const labels = document.querySelectorAll('.engine-radio-label');
    labels.forEach(label => {
      const radio = label.querySelector('input[type="radio"]');
      radio.addEventListener('change', () => {
        labels.forEach(l => l.classList.remove('active'));
        if (radio.checked) {
          label.classList.add('active');
        }
      });
    });
  }

  /* ==========================================================================
     4. OSINT Query Generator Pipeline
     ========================================================================== */
  function initEventListeners() {
    // OSINT Form Submit
    if (elements.dorkForm) {
      elements.dorkForm.addEventListener('submit', handleDorkSubmit);
    }

    // Copy All Dorks
    if (elements.copyAllDorksBtn) {
      elements.copyAllDorksBtn.addEventListener('click', copyAllDorkQueries);
    }

    // Export Dropdowns toggle
    setupDropdown(elements.exportDorksDropdownBtn, elements.dorksExportMenu);
    setupDropdown(elements.exportAnalysisDropdownBtn, elements.analysisExportMenu);

    // Export options click
    document.querySelectorAll('.export-option').forEach(btn => {
      btn.addEventListener('click', handleExportDownload);
    });

    // URL Analyzer Form Submit
    if (elements.analyzerForm) {
      elements.analyzerForm.addEventListener('submit', handleAnalyzerSubmit);
    }

    // Copy Analysis Summary
    if (elements.copyAnalysisSummaryBtn) {
      elements.copyAnalysisSummaryBtn.addEventListener('click', copyAnalysisSummary);
    }

    // Hop Detail Modal close buttons
    const closeHopBtn = document.getElementById('closeHopModalBtn');
    const closeHopFooterBtn = document.getElementById('closeHopDetailFooterBtn');
    if (closeHopBtn) closeHopBtn.addEventListener('click', closeHopModal);
    if (closeHopFooterBtn) closeHopFooterBtn.addEventListener('click', closeHopModal);

    // Analysis View Filter Buttons (All Formatted Data vs Specific Section)
    document.querySelectorAll('.view-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const targetView = btn.getAttribute('data-view');
        document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        if (targetView === 'all') {
          if (elements.analysisTabPanels) {
            elements.analysisTabPanels.classList.add('show-all');
          }
          document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('active'));
        } else {
          if (elements.analysisTabPanels) {
            elements.analysisTabPanels.classList.remove('show-all');
          }
          document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
          const panel = document.getElementById(targetView);
          if (panel) {
            panel.classList.add('active');
            panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          }
        }
      });
    });

    // Backward compatibility for tab-btn if clicked
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const targetTab = btn.getAttribute('data-tab');
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));

        btn.classList.add('active');
        const panel = document.getElementById(targetTab);
        if (panel) panel.classList.add('active');
      });
    });

    // Knowledge Base Sub-Navigation Tabs
    document.querySelectorAll('.kb-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const targetKb = btn.getAttribute('data-kb');
        document.querySelectorAll('.kb-tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.kb-panel').forEach(p => p.classList.remove('active'));

        btn.classList.add('active');
        const panel = document.getElementById(targetKb);
        if (panel) panel.classList.add('active');
      });
    });

    // Close dropdowns when clicking outside
    document.addEventListener('click', (e) => {
      if (!e.target.closest('.export-dropdown-wrapper')) {
        if (elements.dorksExportMenu) elements.dorksExportMenu.classList.remove('show');
        if (elements.analysisExportMenu) elements.analysisExportMenu.classList.remove('show');
      }
    });
  }

  function setupDropdown(btn, menu) {
    if (!btn || !menu) return;
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      menu.classList.toggle('show');
    });
  }

  async function handleDorkSubmit(e) {
    e.preventDefault();

    const domain = elements.dorkDomain.value.trim();
    if (!domain) {
      showToast('Please enter a target domain name.', 'error');
      elements.dorkDomain.focus();
      return;
    }

    if (!elements.dorkAuthorized.checked) {
      showToast('Please check the authorization acknowledgment.', 'error');
      elements.dorkAuthorized.focus();
      return;
    }

    // Gather selected categories
    const selectedCats = [];
    document.querySelectorAll('.category-chip input:checked').forEach(cb => {
      selectedCats.push(cb.value);
    });

    if (selectedCats.length === 0) {
      showToast('Please select at least one intelligence category.', 'error');
      return;
    }

    const activeEngineRadio = document.querySelector('input[name="searchEngine"]:checked');
    const engine = activeEngineRadio ? activeEngineRadio.value : 'google';

    // UI Loading state
    elements.generateDorksBtn.classList.add('loading');
    elements.generateDorksBtn.disabled = true;

    try {
      const response = await fetch('/api/dorks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain: domain,
          categories: selectedCats,
          engine: engine,
          authorized: true
        })
      });

      const result = await response.json();

      if (!response.ok || !result.success) {
        throw new Error(result.error || `HTTP ${response.status}`);
      }

      window.currentDorksData = result.data;
      localStorage.setItem('last_dork_domain', domain);
      renderDorkResults(result.data);
      showToast(`Generated ${result.data.total_queries} queries for ${result.data.domain}`, 'success');

      // Smooth scroll to results
      elements.dorkResultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });

    } catch (err) {
      showToast(`Error: ${err.message}`, 'error');
    } finally {
      elements.generateDorksBtn.classList.remove('loading');
      elements.generateDorksBtn.disabled = false;
    }
  }

  function renderDorkResults(data) {
    elements.dorkResultsContainer.classList.remove('hidden');
    elements.dorkResultsCountBadge.textContent = `${data.total_queries} Queries`;
    elements.dorkTargetDomainBadge.textContent = data.domain;

    // Build Category Filter Pills
    elements.dorkCategoryFilters.innerHTML = `
      <button type="button" class="filter-pill active" data-filter="all">All (${data.total_queries})</button>
    `;

    Object.values(data.categories).forEach(cat => {
      const pill = document.createElement('button');
      pill.type = 'button';
      pill.className = 'filter-pill';
      pill.setAttribute('data-filter', cat.category_id);
      pill.textContent = `${cat.name} (${cat.count})`;
      elements.dorkCategoryFilters.appendChild(pill);
    });

    // Render Query Cards
    renderDorkCards('all');

    // Filter pill click listener
    elements.dorkCategoryFilters.querySelectorAll('.filter-pill').forEach(pill => {
      pill.addEventListener('click', () => {
        elements.dorkCategoryFilters.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        renderDorkCards(pill.getAttribute('data-filter'));
      });
    });
  }

  function renderDorkCards(filterId) {
    if (!window.currentDorksData) return;
    elements.dorkCardsGrid.innerHTML = '';

    const categories = window.currentDorksData.categories;
    const engine = window.currentDorksData.engine;

    Object.values(categories).forEach(cat => {
      if (filterId !== 'all' && cat.category_id !== filterId) return;

      cat.queries.forEach(q => {
        const card = document.createElement('div');
        card.className = 'dork-card';
        card.setAttribute('data-category', cat.category_id);

        card.innerHTML = `
          <div>
            <div class="dork-card-header">
              <span class="dork-label">${escapeHtml(q.label)}</span>
              <span class="dork-category-badge">${escapeHtml(cat.name)}</span>
            </div>
            <p class="dork-desc">${escapeHtml(q.description)}</p>
            <div class="dork-query-box">
              <code class="dork-query-code">${escapeHtml(q.query)}</code>
            </div>
          </div>
          <div class="dork-card-footer">
            <button type="button" class="btn btn-sm btn-outline copy-dork-btn">
              <i class="fas fa-copy"></i> Copy Query
            </button>
            <a href="${escapeHtml(q.search_url)}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-primary">
              <i class="fas fa-external-link-alt"></i> Open in ${capitalize(engine)}
            </a>
          </div>
        `;

        // Wire copy button
        const copyBtn = card.querySelector('.copy-dork-btn');
        copyBtn.addEventListener('click', () => {
          copyToClipboard(q.query);
          showToast(`Copied query: "${q.label}"`, 'success');
        });

        elements.dorkCardsGrid.appendChild(card);
      });
    });

    initTilt();
  }

  function copyAllDorkQueries() {
    if (!window.currentDorksData) return;
    const lines = [];
    Object.values(window.currentDorksData.categories).forEach(cat => {
      cat.queries.forEach(q => {
        lines.push(`# ${q.label} [${cat.name}]`);
        lines.push(q.query);
        lines.push('');
      });
    });

    copyToClipboard(lines.join('\n'));
    showToast(`Copied all ${window.currentDorksData.total_queries} queries to clipboard!`, 'success');
  }

  /* ==========================================================================
     5. URL Analyzer Pipeline
     ========================================================================== */
  async function handleAnalyzerSubmit(e) {
    e.preventDefault();

    const rawUrl = elements.analyzerUrl.value.trim();
    if (!rawUrl) {
      showToast('Please enter a target URL to analyze.', 'error');
      elements.analyzerUrl.focus();
      return;
    }

    if (!elements.analyzerAuthorized.checked) {
      showToast('Please check the authorization acknowledgment.', 'error');
      elements.analyzerAuthorized.focus();
      return;
    }

    // UI Scanner state
    elements.analyzeUrlBtn.classList.add('loading');
    elements.analyzeUrlBtn.disabled = true;
    elements.scannerOverlay.classList.remove('hidden');
    elements.analyzerResultsContainer.classList.add('hidden');

    // Scanning progress text simulation
    const steps = [
      'Resolving DNS records and evaluating SSL handshake...',
      'Tracing redirect chain and checking for protocol downgrades...',
      'Evaluating heuristic threat rules for homoglyphs and deception...',
      'Compiling risk telemetry report...'
    ];
    let stepIndex = 0;
    const progressInterval = setInterval(() => {
      stepIndex = (stepIndex + 1) % steps.length;
      if (elements.scannerProgressText) {
        elements.scannerProgressText.textContent = steps[stepIndex];
      }
    }, 700);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: rawUrl,
          authorized: true
        })
      });

      const result = await response.json();

      if (!response.ok || !result.success) {
        throw new Error(result.error || `HTTP ${response.status}`);
      }

      window.currentAnalysisData = result.data;
      localStorage.setItem('last_analyzer_url', rawUrl);
      if (elements.analyzerUrl && result.data.url) {
        elements.analyzerUrl.value = result.data.url;
      }

      // Hide scanner before rendering results so scrollIntoView aligns smoothly
      elements.scannerOverlay.classList.add('hidden');
      clearInterval(progressInterval);

      renderAnalysisResults(result.data);
      showToast(`Scan complete: ${result.data.risk.level} Risk (${result.data.risk.score}/100)`, 'success');

      // Scroll smoothly to results
      elements.analyzerResultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });

    } catch (err) {
      showToast(`Analysis Failed: ${err.message}`, 'error');
    } finally {
      clearInterval(progressInterval);
      elements.scannerOverlay.classList.add('hidden');
      elements.analyzeUrlBtn.classList.remove('loading');
      elements.analyzeUrlBtn.disabled = false;
    }
  }

  function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = (val !== null && val !== undefined) ? String(val) : '-';
  }

  function setHtml(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = (html !== null && html !== undefined) ? String(html) : '';
  }

  function renderAnalysisResults(data) {
    if (!data) return;
    const container = document.getElementById('analyzerResultsContainer');
    if (container) container.classList.remove('hidden');

    const risk = data.risk || {};
    const score = (typeof risk.score === 'number') ? risk.score : 0;
    const level = risk.level || 'Low';
    const structure = data.structure || {};
    const domainDetails = data.domain_details || {};
    const redirects = data.redirects || {};
    const flags = data.flags || [];
    const ssl = domainDetails.ssl || {};
    const whois = domainDetails.whois || {};

    // 1. Circular Risk Gauge Animation (SVG-safe: avoid direct .className assignment on SVGCircleElement)
    try {
      const meter = document.getElementById('riskGaugeMeter');
      const circumference = 314.159; // 2 * PI * 50
      const offset = Math.max(0, circumference - (score / 100) * circumference);
      if (meter) {
        meter.style.strokeDasharray = `${circumference}`;
        meter.style.strokeDashoffset = `${offset}`;
        meter.setAttribute('stroke-dashoffset', String(offset));
        const riskClass = level === 'High' ? 'risk-high' : (level === 'Medium' ? 'risk-medium' : 'risk-low');
        meter.setAttribute('class', `gauge-meter ${riskClass}`);
      }
    } catch (e) {
      console.warn('Error setting SVG gauge meter:', e);
    }

    // Risk Level Badge
    const badge = document.getElementById('riskLevelBadge');
    if (badge) {
      badge.className = 'risk-level-badge';
      if (level === 'High') {
        badge.classList.add('level-high');
        badge.textContent = `HIGH RISK (${score}%)`;
      } else if (level === 'Medium') {
        badge.classList.add('level-medium');
        badge.textContent = `MEDIUM RISK (${score}%)`;
      } else {
        badge.classList.add('level-low');
        badge.textContent = `LOW RISK (${score}%)`;
      }
    }

    // Animate score counter inside gauge
    const scoreValEl = document.getElementById('riskScoreValue');
    if (scoreValEl) {
      animateNumber(scoreValEl, score);
    }

    // Update prominent Risk Percentage metric pill in metrics ribbon
    const riskPill = document.getElementById('metricRiskPercentage');
    if (riskPill) {
      riskPill.textContent = `${score}%`;
      riskPill.className = `metric-val ${score >= 70 ? 'text-red' : (score >= 30 ? 'text-yellow' : 'text-green')}`;
    }

    // Populate Primary IP and Safety Index in Metrics Ribbon
    const primaryIp = (domainDetails.ipv4 && domainDetails.ipv4.length > 0)
      ? domainDetails.ipv4[0]
      : (domainDetails.host || 'Unresolved');
    setText('metricIp', primaryIp);

    const safetyVal = (risk.safety_score !== undefined) ? risk.safety_score : Math.max(0, 100 - score);
    const safetyEl = document.getElementById('metricSafety');
    if (safetyEl) {
      safetyEl.textContent = `${safetyVal}% Safe`;
      safetyEl.className = `metric-val ${safetyVal >= 70 ? 'text-green' : (safetyVal >= 40 ? 'text-yellow' : 'text-red')}`;
    }

    setText('riskTargetUrl', data.url || '-');
    setText('riskNarrativeText', risk.summary || 'Passive reconnaissance completed successfully.');

    // Quick Metrics
    setText('metricScheme', structure.scheme ? structure.scheme.toUpperCase() : 'HTTPS');
    setText('metricTld', structure.tld ? `.${structure.tld}` : '(none)');
    setText('metricLength', `${structure.length || 0} chars`);
    setText('metricSsl', ssl.enabled ? 'Active' : 'Inactive');
    setText('metricHops', redirects.hop_count !== undefined ? redirects.hop_count : 0);
    setText('metricFlags', flags.length);
    setText('flagsTabCount', flags.length);

    // 2. Set All-In-One Formatted View (ensures URL Structure, Domain/DNS/IP, SSL, Redirects & Flags are all visible simultaneously)
    const panels = document.getElementById('analysisTabPanels');
    if (panels) panels.classList.add('show-all');

    document.querySelectorAll('.view-btn').forEach(b => {
      b.classList.toggle('active', b.getAttribute('data-view') === 'all');
    });
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('active'));

    // 3. Tab 1: Structure Table
    try {
      renderStructureTable(structure);
    } catch (e) {
      console.error('Error rendering structure table:', e);
    }

    // 4. Tab 2: Domain, DNS, IP & SSL
    try {
      renderDomainAndSsl(domainDetails);
    } catch (e) {
      console.error('Error rendering domain & ssl:', e);
    }

    // 5. Tab 3: Redirect Sequence Timeline
    try {
      renderRedirectTimeline(redirects);
    } catch (e) {
      console.error('Error rendering redirect timeline:', e);
    }

    // 6. Tab 4: Security Flags Grid
    try {
      renderSecurityFlags(flags);
    } catch (e) {
      console.error('Error rendering security flags:', e);
    }



    // 8. Feature 2: Redirect Visualizer
    try {
      renderRedirectVisualizer(redirects);
    } catch (e) {
      console.error('Error rendering redirect visualizer:', e);
    }



    initTilt();
  }

  function renderStructureTable(structure) {
    if (!structure) return;

    const rows = [
      { comp: 'Scheme (Protocol)', val: structure.scheme || 'http', note: structure.scheme === 'https' ? 'Encrypted TLS' : 'Unencrypted Cleartext' },
      { comp: 'Host (Netloc)', val: structure.host || '-', note: structure.host || '-' },
      { comp: 'Subdomain', val: structure.subdomain || '(none)', note: structure.subdomain ? `${structure.subdomain.split('.').length} levels` : 'No subdomain' },
      { comp: 'Registered Domain', val: structure.domain || '-', note: 'Primary identity' },
      { comp: 'Top-Level Domain (TLD)', val: structure.tld ? `.${structure.tld}` : '(none)', note: structure.tld || '(none)' },
      { comp: 'Port', val: structure.port || (structure.scheme === 'https' ? 443 : 80), note: structure.is_standard_port ? 'Standard Web Port' : 'Non-standard port' },
      { comp: 'Path', val: structure.path || '/', note: `${structure.path_length || (structure.path ? structure.path.length : 1)} characters` },
      { comp: 'Query String', val: structure.query_string || '(empty)', note: `${structure.query_param_count || 0} parameters` },
      { comp: 'Fragment', val: structure.fragment || '(none)', note: 'Client-side anchor' },
      { comp: 'Total URL Length', val: `${structure.length || 0} characters`, note: (structure.length || 0) > 75 ? 'Elevated Length' : 'Normal Length' }
    ];

    const body = document.getElementById('structureTableBody');
    if (body) {
      body.innerHTML = rows.map(r => `
        <tr>
          <td><strong>${escapeHtml(r.comp)}</strong></td>
          <td><code>${escapeHtml(String(r.val))}</code></td>
          <td class="text-muted">${escapeHtml(r.note)}</td>
        </tr>
      `).join('');
    }

    setText('queryParamCountLabel', structure.query_param_count || 0);
    const queryContainer = document.getElementById('queryParamsListContainer');
    if (queryContainer) {
      if (structure.query_params && structure.query_params.length > 0) {
        queryContainer.innerHTML = `
          <table class="cyber-table compact-table">
            <thead>
              <tr><th>Parameter Key</th><th>Assigned Value</th></tr>
            </thead>
            <tbody>
              ${structure.query_params.map(p => `
                <tr>
                  <td><code>${escapeHtml(p.key)}</code></td>
                  <td><code>${escapeHtml(p.value)}</code></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        `;
      } else {
        queryContainer.innerHTML = '<p class="text-muted">No query parameters present in URL.</p>';
      }
    }
  }

  function renderDomainAndSsl(domainDetails) {
    if (!domainDetails) return;

    setText('dnsDomainValue', domainDetails.domain || '-');
    setText('dnsHostValue', domainDetails.host || '-');

    // Primary IP Callout
    const primaryIpDisplay = document.getElementById('primaryIpDisplay');
    if (primaryIpDisplay) {
      if (domainDetails.ipv4 && domainDetails.ipv4.length > 0) {
        primaryIpDisplay.textContent = domainDetails.ipv4.join('  •  ');
      } else {
        primaryIpDisplay.textContent = domainDetails.host ? `Unresolved (${domainDetails.host})` : 'None / Offline';
      }
    }

    // IPv4
    const ipv4Tags = document.getElementById('dnsIpv4Tags');
    if (ipv4Tags) {
      if (domainDetails.ipv4 && domainDetails.ipv4.length > 0) {
        ipv4Tags.innerHTML = domainDetails.ipv4.map(ip => `<span class="cyber-tag">${escapeHtml(ip)}</span>`).join('');
      } else {
        ipv4Tags.innerHTML = '<span class="cyber-tag">Unresolved</span>';
      }
    }

    // IPv6
    const ipv6Tags = document.getElementById('dnsIpv6Tags');
    if (ipv6Tags) {
      if (domainDetails.ipv6 && domainDetails.ipv6.length > 0) {
        ipv6Tags.innerHTML = domainDetails.ipv6.map(ip => `<span class="cyber-tag">${escapeHtml(ip)}</span>`).join('');
      } else {
        ipv6Tags.innerHTML = '<span class="cyber-tag">None</span>';
      }
    }

    setText('dnsPtrValue', domainDetails.reverse_dns || 'No PTR Record');

    // WHOIS
    const whois = domainDetails.whois || {};
    setText('whoisRegistrar', whois.registrar || 'Unavailable');
    const ageText = (whois.age_days !== null && whois.age_days !== undefined)
      ? `${whois.age_days} days (${(whois.age_days / 365.25).toFixed(1)} yrs)`
      : 'Unavailable';
    setText('whoisAge', ageText);
    setText('whoisCreated', whois.creation_date || 'Unavailable');
    setText('whoisExpires', whois.expiration_date || 'Unavailable');

    // SSL
    const ssl = domainDetails.ssl || {};
    const sslNotice = document.getElementById('sslStatusNotice');
    if (ssl.enabled) {
      if (sslNotice) {
        sslNotice.innerHTML = `
          <div class="alert-box alert-success mb-3" style="background: rgba(0, 245, 160, 0.1); border: 1px solid var(--neon-green); color: var(--neon-green); padding: 0.6rem 0.85rem; border-radius: 6px;">
            <i class="fas fa-check-shield"></i> SSL Handshake Succeeded (CA Trusted)
          </div>
        `;
      }
      setText('sslIssuer', ssl.issuer || 'Unknown');
      setText('sslSubject', ssl.subject || 'Unknown');
      setText('sslValidFrom', ssl.valid_from || 'Unknown');
      setText('sslValidTo', ssl.valid_to || 'Unknown');
      const daysText = (ssl.days_remaining !== null && ssl.days_remaining !== undefined)
        ? `${ssl.days_remaining} days ${ssl.is_expired ? '(EXPIRED)' : 'remaining'}`
        : 'Unknown';
      setText('sslDaysRemaining', daysText);
      setText('sslSelfSigned', ssl.is_self_signed ? 'YES (Untrusted)' : 'No (CA Verified)');

      const sanTags = document.getElementById('sslSanTags');
      if (sanTags) {
        if (ssl.sans && ssl.sans.length > 0) {
          sanTags.innerHTML = ssl.sans.map(san => `<span class="cyber-tag">${escapeHtml(san)}</span>`).join('');
        } else {
          sanTags.innerHTML = '<span class="cyber-tag">None</span>';
        }
      }
    } else {
      if (sslNotice) {
        sslNotice.innerHTML = `
          <div class="alert-box alert-warning mb-3" style="background: rgba(245, 158, 11, 0.1); border: 1px solid var(--neon-yellow); color: var(--neon-yellow); padding: 0.6rem 0.85rem; border-radius: 6px;">
            <i class="fas fa-exclamation-triangle"></i> ${escapeHtml(ssl.error || 'SSL not active on this target')}
          </div>
        `;
      }
      setText('sslIssuer', 'N/A');
      setText('sslSubject', 'N/A');
      setText('sslValidFrom', 'N/A');
      setText('sslValidTo', 'N/A');
      setText('sslDaysRemaining', 'N/A');
      setText('sslSelfSigned', 'N/A');
      setHtml('sslSanTags', '<span class="cyber-tag">N/A</span>');
    }
  }

  function renderRedirectTimeline(redirects) {
    if (!redirects) return;

    setText('redirectHopCountBadge', `${redirects.hop_count || 0} Hops`);

    const downgradeBadge = document.getElementById('redirectDowngradeBadge');
    if (downgradeBadge) {
      if (redirects.is_downgraded) {
        downgradeBadge.className = 'badge text-red';
        downgradeBadge.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Protocol Downgrade (HTTPS → HTTP)';
      } else if (redirects.is_upgraded) {
        downgradeBadge.className = 'badge text-green';
        downgradeBadge.innerHTML = '<i class="fas fa-shield-alt"></i> HTTPS Upgrade Enforced';
      } else {
        downgradeBadge.className = 'badge text-green';
        downgradeBadge.textContent = 'Encrypted / No Downgrade';
      }
    }

    const crossDomainBadge = document.getElementById('redirectCrossDomainBadge');
    if (crossDomainBadge) {
      if (redirects.is_cross_domain) {
        crossDomainBadge.className = 'badge text-yellow';
        crossDomainBadge.innerHTML = '<i class="fas fa-external-link-alt"></i> Cross-Domain Redirect';
      } else {
        crossDomainBadge.className = 'badge text-green';
        crossDomainBadge.textContent = 'Same Domain';
      }
    }

    const container = document.getElementById('redirectTimelineContainer');
    if (container) {
      const chain = redirects.chain || [];
      if (chain.length === 0) {
        container.innerHTML = '<p class="text-muted">No redirect hops recorded (direct response).</p>';
        return;
      }

      container.innerHTML = chain.map(hop => {
        let statusClass = 'status-2xx';
        if (hop.status_code >= 300 && hop.status_code < 400) statusClass = 'status-3xx';
        else if (hop.status_code >= 400 || hop.status_code === 0) statusClass = 'status-4xx';

        return `
          <div class="timeline-hop">
            <div class="timeline-marker">${hop.hop}</div>
            <div class="timeline-card">
              <div class="timeline-header">
                <span class="status-badge ${statusClass}">Status ${hop.status_code}</span>
                <span class="text-muted" style="font-size: 0.78rem;">${escapeHtml(hop.reason || '')}</span>
              </div>
              <div class="timeline-url"><code>${escapeHtml(hop.url)}</code></div>
              ${hop.next_url ? `
                <div class="timeline-next text-muted" style="font-size: 0.8rem; margin-top: 0.4rem;">
                  <i class="fas fa-arrow-right neon-cyan"></i> Redirects to: <code>${escapeHtml(hop.next_url)}</code>
                </div>
              ` : ''}
            </div>
          </div>
        `;
      }).join('');
    }
  }

  function renderSecurityFlags(flags) {
    const container = document.getElementById('flagsGridContainer');
    if (!container) return;

    if (!flags || flags.length === 0) {
      container.innerHTML = `
        <div class="flag-card" style="grid-column: 1 / -1; text-align: center; padding: 2.5rem 1rem;">
          <div style="font-size: 2.2rem; color: var(--neon-green); margin-bottom: 0.5rem;">
            <i class="fas fa-shield-check"></i>
          </div>
          <h5 style="font-size: 1.15rem; font-weight: 700; color: var(--neon-green);">No Malicious Threat Flags Triggered</h5>
          <p class="text-muted" style="max-width: 540px; margin: 0.5rem auto 0;">
            The analyzed URL adheres to RFC structural standards and standard domain infrastructure. No active brand impersonation, deceptive homoglyphs, or credential phishing traits were detected.
          </p>
        </div>
      `;
      return;
    }

    container.innerHTML = flags.map(f => {
      const sev = (f.severity || 'info').toLowerCase();
      return `
        <div class="flag-card sev-${sev}">
          <div class="flag-header">
            <span class="flag-title">${escapeHtml(f.name)}</span>
            <span class="severity-pill severity-${sev}">${escapeHtml(sev)}</span>
          </div>
          <p class="flag-explanation">${escapeHtml(f.explanation)}</p>
          <div class="flag-footer" style="display: flex; justify-content: space-between; font-size: 0.75rem; color: var(--text-muted); margin-top: 0.4rem;">
            <span>Rule ID: <code>${escapeHtml(f.rule_id || 'RULE')}</code></span>
            <span>Risk Impact: +${f.weight || 0} pts</span>
          </div>
        </div>
      `;
    }).join('');
  }

  function copyAnalysisSummary() {
    if (!window.currentAnalysisData) return;
    const data = window.currentAnalysisData;
    const text = [
      `Target URL: ${data.url}`,
      `Risk Score: ${data.risk.score}/100 (${data.risk.level} Risk)`,
      `Summary: ${data.risk.summary}`,
      `Detected Flags: ${data.flags.length}`,
      ...data.flags.map(f => `- [${f.severity.toUpperCase()}] ${f.name}: ${f.explanation}`)
    ].join('\n');

    copyToClipboard(text);
    showToast('Analysis summary copied to clipboard!', 'success');
  }

  /* ==========================================================================
     6. Exporting Files (TXT, CSV, JSON)
     ========================================================================== */
  async function handleExportDownload(e) {
    const btn = e.currentTarget;
    const format = btn.getAttribute('data-format');
    const type = btn.getAttribute('data-type'); // 'dorks' or 'analysis'

    if (format === 'pdf') {
      const openPdfBtn = document.getElementById('openPdfModalBtn');
      if (openPdfBtn) {
        openPdfBtn.click();
        if (elements.analysisExportMenu) elements.analysisExportMenu.classList.remove('show');
        return;
      }
    }

    const payloadData = type === 'dorks' ? window.currentDorksData : window.currentAnalysisData;

    if (!payloadData) {
      showToast('No active report data to export.', 'error');
      return;
    }

    try {
      showToast(`Generating ${format.toUpperCase()} report...`, 'info');

      const response = await fetch('/api/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: format,
          report_type: type,
          data: payloadData,
          authorized: true
        })
      });

      if (!response.ok) {
        throw new Error(`Export failed with HTTP ${response.status}`);
      }

      // Convert to downloadable blob
      const blob = await response.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;

      // Extract filename from Content-Disposition if present
      const disposition = response.headers.get('Content-Disposition');
      let filename = `security_intel_${type}.${format}`;
      if (disposition && disposition.indexOf('filename=') !== -1) {
        const matches = /filename="([^"]+)"/.exec(disposition);
        if (matches && matches[1]) filename = matches[1];
      }

      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(downloadUrl);

      showToast(`Saved report as ${filename}`, 'success');

      // Close dropdown
      if (elements.dorksExportMenu) elements.dorksExportMenu.classList.remove('show');
      if (elements.analysisExportMenu) elements.analysisExportMenu.classList.remove('show');

    } catch (err) {
      showToast(`Export Error: ${err.message}`, 'error');
    }
  }

  /* ==========================================================================
     FEATURE 2: Redirect Visualizer & Hop Modal
     ========================================================================== */
  function renderRedirectVisualizer(redirects) {
    const container = document.getElementById('redirectNodesContainer');
    if (!container) return;

    const chain = (redirects && (redirects.redirect_chain || redirects.chain)) || [];

    if (chain.length === 0) {
      container.innerHTML = `
        <div style="padding: 1.25rem; text-align: center; width: 100%; color: var(--text-secondary);">
          <i class="fas fa-check-circle text-green" style="font-size: 1.5rem; margin-bottom: 0.5rem; display: block;"></i>
          <strong>Direct Destination</strong> — No redirect hops observed for target.
        </div>
      `;
      return;
    }

    let html = '';
    chain.forEach((hop, idx) => {
      const isLast = (idx === chain.length - 1);
      let nodeClass = 'node-same';
      if (hop.is_loop || hop.is_https_downgrade) {
        nodeClass = 'node-danger';
      } else if (hop.is_cross_domain) {
        nodeClass = 'node-cross';
      } else if (isLast) {
        nodeClass = 'node-final';
      }

      let statusBadgeClass = 'status-2xx';
      if (hop.status_code >= 300 && hop.status_code < 400) statusBadgeClass = 'status-3xx';
      else if (hop.status_code >= 400 || hop.status_code === 0) statusBadgeClass = 'status-4xx';

      html += `
        <div class="redirect-node-card ${nodeClass}" data-hop-index="${idx}" title="Click to view complete hop headers">
          ${hop.is_loop ? '<span class="node-loop-indicator">LOOP</span>' : ''}
          <div class="node-top-bar">
            <span class="node-hop-num">Hop #${hop.hop}</span>
            <span class="status-badge ${statusBadgeClass}">${hop.status_code}</span>
          </div>
          <div class="node-domain-text" title="${escapeHtml(hop.domain || hop.url)}">
            ${escapeHtml(hop.domain || 'Endpoint')}
          </div>
          <div class="node-footer-meta">
            <span><i class="fas fa-stopwatch"></i> ${hop.response_time_ms !== undefined ? hop.response_time_ms.toFixed(1) + 'ms' : '< 1ms'}</span>
            <span>${isLast ? '<strong class="neon-cyan">FINAL</strong>' : (hop.is_cross_domain ? '<span class="text-yellow">CROSS</span>' : '<span class="text-green">SAME</span>')}</span>
          </div>
        </div>
      `;

      if (!isLast) {
        html += `
          <div class="node-arrow" aria-hidden="true">
            <i class="fas fa-chevron-right"></i>
          </div>
        `;
      }
    });

    container.innerHTML = html;

    // Attach click listener to nodes to open hop modal
    container.querySelectorAll('.redirect-node-card').forEach(card => {
      card.addEventListener('click', () => {
        const idx = parseInt(card.getAttribute('data-hop-index'), 10);
        const hopData = chain[idx];
        if (hopData) openHopModal(hopData);
      });
    });

    // Animate with GSAP if available
    if (window.gsap) {
      gsap.from('#redirectNodesContainer .redirect-node-card', {
        duration: 0.45,
        opacity: 0,
        y: 12,
        stagger: 0.1,
        ease: 'power2.out'
      });
    }
  }

  function openHopModal(hop) {
    const modal = document.getElementById('hopDetailModal');
    if (!modal) return;

    setText('hopModalSubtitle', `Hop #${hop.hop} Telemetry Breakdown`);
    setText('hopDetailStatus', `${hop.status_code} ${hop.reason || ''}`);
    setText('hopDetailLatency', hop.response_time_ms !== undefined ? `${hop.response_time_ms.toFixed(1)} ms` : 'N/A');
    setText('hopDetailUrl', hop.url || '-');

    const nextRow = document.getElementById('hopDetailNextRow');
    if (hop.next_url || hop.location_header) {
      if (nextRow) nextRow.style.display = 'flex';
      setText('hopDetailNext', hop.next_url || hop.location_header);
    } else {
      if (nextRow) nextRow.style.display = 'none';
    }

    let typeText = 'Direct Request / Destination';
    if (hop.is_loop) typeText = '⚠️ Infinite Redirect Loop Trapped';
    else if (hop.is_https_downgrade) typeText = '🚨 Protocol Downgrade (HTTPS → HTTP Insecure)';
    else if (hop.is_cross_domain) typeText = '⚡ Cross-Domain Redirect Jump';
    else if (hop.status_code >= 300 && hop.status_code < 400) typeText = 'Standard Same-Domain HTTP Redirect';

    setText('hopDetailType', typeText);
    modal.classList.remove('hidden');
    modal.classList.add('show');
    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
  }

  function closeHopModal() {
    const modal = document.getElementById('hopDetailModal');
    if (modal) {
      modal.classList.add('hidden');
      modal.classList.remove('show');
      modal.style.display = 'none';
    }
    document.body.style.overflow = '';
  }

  function getDomainFromUrl(rawUrl) {
    try {
      if (!rawUrl) return 'default';
      const parsed = new URL(rawUrl.startsWith('http') ? rawUrl : 'https://' + rawUrl);
      return parsed.hostname;
    } catch {
      return 'default';
    }
  }

  /* ==========================================================================
     FEATURE 4: PDF Report Generation & Export
     ========================================================================== */
  function initPdfExport() {
    const openBtn = document.getElementById('openPdfModalBtn');
    const modal = document.getElementById('pdfReportModal');
    const closeBtn = document.getElementById('closePdfModalBtn');
    const cancelBtn = document.getElementById('cancelPdfModalBtn');
    const confirmBtn = document.getElementById('confirmGeneratePdfBtn');

    function openPdfModal() {
      if (!window.currentAnalysisData) {
        showToast('Please analyze a URL first before generating a PDF report.', 'error');
        return;
      }
      if (modal) {
        // Pre-fill target domain in title if available
        const titleInput = document.getElementById('pdfReportTitleInput');
        if (titleInput && window.currentAnalysisData.url) {
          try {
            const host = new URL(window.currentAnalysisData.url).hostname;
            titleInput.value = `URL Security & Threat Assessment - ${host}`;
          } catch {
            titleInput.value = 'URL Security & Threat Assessment Report';
          }
        }
        modal.classList.remove('hidden');
        modal.classList.add('show');
        modal.style.display = 'flex';
        document.body.style.overflow = 'hidden';
      }
    }

    function closePdfModal() {
      if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('show');
        modal.style.display = 'none';
      }
      document.body.style.overflow = '';
    }

    if (openBtn) {
      openBtn.addEventListener('click', (e) => {
        e.preventDefault();
        openPdfModal();
      });
    }

    if (closeBtn) closeBtn.addEventListener('click', closePdfModal);
    if (cancelBtn) cancelBtn.addEventListener('click', closePdfModal);
    if (modal) {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) closePdfModal();
      });
    }

    if (confirmBtn) {
      confirmBtn.addEventListener('click', async () => {
        if (!window.currentAnalysisData) {
          showToast('No active URL analysis data found.', 'error');
          return;
        }

        const reportTitle = document.getElementById('pdfReportTitleInput')?.value.trim() || 'URL Threat Assessment Report';
        const preparedBy = document.getElementById('pdfPreparedByInput')?.value.trim() || 'Cybersecurity Analyst';
        const includeDorks = document.getElementById('pdfIncludeDorksCheck')?.checked ?? true;

        confirmBtn.disabled = true;
        confirmBtn.querySelector('.spinner')?.classList.remove('hidden');
        confirmBtn.querySelector('.btn-text')?.classList.add('hidden');

        try {
          showToast('Compiling executive PDF assessment...', 'info');

          const payload = {
            report_title: reportTitle,
            prepared_by: preparedBy,
            data: window.currentAnalysisData,
            dorks: (includeDorks && window.currentDorksData) ? (window.currentDorksData.categories || window.currentDorksData) : null,
            dorks_data: (includeDorks && window.currentDorksData) ? window.currentDorksData : null,
            authorized: true
          };

          const response = await fetch('/api/report/pdf', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          });

          if (!response.ok) {
            const errJson = await response.json().catch(() => ({}));
            throw new Error(errJson.error || `HTTP ${response.status}`);
          }

          const blob = await response.blob();
          const downloadUrl = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = downloadUrl;
          const hostPart = (window.currentAnalysisData.domain_details?.host || 'target').replace(/[^a-zA-Z0-9.-]/g, '_');
          a.download = `Security_Assessment_${hostPart}_${Date.now()}.pdf`;
          document.body.appendChild(a);
          a.click();
          a.remove();
          window.URL.revokeObjectURL(downloadUrl);

          showToast('Executive PDF Report downloaded successfully!', 'success');
          closePdfModal();
        } catch (err) {
          showToast(`PDF Generation Error: ${err.message}`, 'error');
        } finally {
          confirmBtn.disabled = false;
          confirmBtn.querySelector('.spinner')?.classList.add('hidden');
          confirmBtn.querySelector('.btn-text')?.classList.remove('hidden');
        }
      });
    }
  }

  /* ==========================================================================
     FEATURE 7: Modern Interactive Help Center, Article Viewer & Contact Ticket
     ========================================================================== */
  const HELP_ARTICLES = {
    'getting-started': {
      category: 'Getting Started',
      badgeClass: 'badge-low',
      icon: 'fas fa-rocket',
      readTime: '2 min read',
      title: 'Getting started with URL Intelligence & Reconnaissance',
      summary: 'Learn how to perform passive domain discovery, inspect URL architectures, analyze redirection chains, and export professional cybersecurity audit reports.',
      steps: [
        {
          title: 'Scope Selection & Authorization',
          desc: 'Input any target domain (e.g. example.com) or full URL. Confirm that your analysis complies with organizational rules of engagement and ethical research standards.'
        },
        {
          title: 'Choose Intelligence Mode',
          desc: 'Switch between OSINT Google Search Dork queries for perimeter discovery and deep URL Intelligence Analysis for RFC architectural deconstruction.'
        },
        {
          title: 'Inspect Telemetry & Routing',
          desc: 'Review resolved IPv4 addresses, DNS nameservers, SSL certificate security, multi-hop redirect pathways, and passive heuristic threat flags.'
        },
        {
          title: 'Generate Audit Reports',
          desc: 'Export parsed intelligence into JSON, CSV, plaintext TXT, or comprehensive ReportLab PDF executive summaries with a single click.'
        }
      ],
      tips: 'All queries performed by this engine are strictly passive — no active exploit payloads or invasive port scans are ever transmitted.'
    },
    'osint-dorks': {
      category: 'OSINT Intelligence',
      badgeClass: 'badge-low',
      icon: 'fas fa-search',
      readTime: '3 min read',
      title: 'OSINT & Google Dorks: Passive Asset Discovery',
      summary: 'Master Google search operators to uncover sensitive exposed files, configuration leaks, database backups, administrative portals, and cloud buckets.',
      steps: [
        {
          title: 'Operator Fundamentals (site:, inurl:, filetype:)',
          desc: 'Target specific domains with "site:example.com", isolate URL path keywords with "inurl:admin", and locate exposed files with "filetype:env" or "filetype:sql".'
        },
        {
          title: 'Targeted Intelligence Categories',
          desc: 'Generate pre-built queries across 9 security categories: Exposed Documents, Directory Listings, Configuration Files, Database Dumps, Login Portals, Cloud Storage, and API Endpoints.'
        },
        {
          title: 'Refining & Eliminating Noise',
          desc: 'Exclude known false positives using negation operators (e.g. -site:help.example.com -inurl:forum) to focus strictly on genuine exposures.'
        },
        {
          title: 'Defensive Remediation',
          desc: 'Disable web server autoindexing (Options -Indexes in Apache), place sensitive endpoints behind SSO/VPN gateways, and enforce robots.txt disallow rules.'
        }
      ],
      tips: 'Regularly audit your organization\'s external domain perimeter with search operators to detect accidental configuration drift before threat actors do.'
    },
    'scans-reports': {
      category: 'Scans & Telemetry',
      badgeClass: 'badge-medium',
      icon: 'fas fa-broadcast-tower',
      readTime: '3 min read',
      title: 'URL Scans, RFC Deconstruction & Risk Telemetry',
      summary: 'Understand how the passive analysis pipeline deconstructs complex URLs, identifies obfuscated parameters, resolves network infrastructure, and computes risk levels.',
      steps: [
        {
          title: 'RFC 3986 Architectural Breakdown',
          desc: 'Deconstruct target URLs into Scheme, Userinfo credentials, Subdomains, Registered Apex Domain, Port, Path hierarchy, Query keys, and Fragments.'
        },
        {
          title: 'Query Parameters & Obfuscation Analysis',
          desc: 'Examine URL parameters for nested base64 payloads, open redirect triggers (dest=, redirect_to=), and tracking telemetry tokens.'
        },
        {
          title: 'Passive Threat Heuristics',
          desc: 'The engine evaluates 12+ risk patterns: Raw IP domains, @ userinfo deception, Punycode homoglyphs, excessive subdomains, and URL shortener masks.'
        },
        {
          title: 'Telemetry Dashboard & Export',
          desc: 'View resolved DNS records, SSL cipher suites, certificate expiration countdowns, and latency in a unified dark glassmorphism dashboard.'
        }
      ],
      tips: 'A 0% threat score confirms no known deceptive patterns were detected in the URL structure, but defense-in-depth is always recommended.'
    },
    'incident-response': {
      category: 'Incident Response',
      badgeClass: 'badge-high',
      icon: 'fas fa-exclamation-triangle',
      readTime: '4 min read',
      title: 'Incident Response Playbook: Handling Active Cyber Threats',
      summary: 'Critical rapid-response protocol for responding to live domain impersonation, credential harvesting, malware distribution, and urgent security breaches.',
      steps: [
        {
          title: 'Immediate Threat Isolation',
          desc: 'Block outbound traffic to malicious endpoints at your perimeter firewall. Sinkhole malicious domains in internal DNS resolvers immediately.'
        },
        {
          title: 'Forensic Preservation',
          desc: 'Capture volatile network telemetry, full HTTP headers, redirect sequences, and raw .eml phishing headers before the hosting provider terminates the server.'
        },
        {
          title: 'Registrar & Abuse Takedown Requests',
          desc: 'Submit urgent domain abuse complaints to the sponsoring registrar, hosting ASN provider, and Google Safe Browsing / Microsoft SmartScreen.'
        },
        {
          title: 'Credential Rotation & User Notification',
          desc: 'Force immediate password resets with mandatory multi-factor authentication for compromised accounts and circulate attack IoCs to the SOC.'
        }
      ],
      tips: 'Under active attack right now? Click "Report an incident" in the Help Center to immediately dispatch emergency incident response details to our team.'
    },
    'account-security': {
      category: 'Account Security',
      badgeClass: 'badge-low',
      icon: 'fas fa-user-shield',
      readTime: '3 min read',
      title: 'Account Security, Identity Hardening & RBAC',
      summary: 'Best practices for securing administrative accounts, deploying phishing-resistant multi-factor authentication, and enforcing least-privilege access controls.',
      steps: [
        {
          title: 'Phishing-Resistant MFA (FIDO2 / WebAuthn)',
          desc: 'Enforce hardware security keys (YubiKey) or RFC 6238 time-based authenticator apps (TOTP). Deprecate insecure SMS-based verification.'
        },
        {
          title: 'Role-Based Access Control (RBAC)',
          desc: 'Enforce least privilege: separate read-only security auditor accounts from administrative engineers with scan configuration privileges.'
        },
        {
          title: 'Passphrase Entropy & Password Managers',
          desc: 'Require 16+ character passphrases composed of random dictionary blocks, eliminating brute-force and credential stuffing vulnerabilities.'
        },
        {
          title: 'Session & API Token Rotation',
          desc: 'Audit active sessions and expire idle connections after 30 minutes. Regularly rotate API keys and audit access timestamps in logging vaults.'
        }
      ],
      tips: 'Never reuse credentials across multiple environments. Store master credentials in zero-knowledge encrypted credential vaults.'
    },
    'dns-ssl': {
      category: 'Infrastructure Security',
      badgeClass: 'badge-low',
      icon: 'fas fa-lock',
      readTime: '3 min read',
      title: 'DNS Resolution, IP Attribution & SSL/TLS Verification',
      summary: 'Deep-dive into Domain Name System queries, resolved IPv4 routing, Certificate Authority trust chains, and cryptographic handshake validity.',
      steps: [
        {
          title: 'DNS Resolution & Autonomous System (ASN)',
          desc: 'Resolve the target domain to primary IPv4 addresses. Cross-reference the hosting ASN to determine whether the host resides on cloud CDNs or bulletproof providers.'
        },
        {
          title: 'SSL/TLS Certificate Authority Verification',
          desc: 'Verify the certificate issuer (DigiCert, Let\'s Encrypt, Sectigo, Cloudflare) and confirm that Subject Alternative Names (SAN) align with the target domain.'
        },
        {
          title: 'Validity Windows & Ephemeral Certificates',
          desc: 'Inspect "Valid From" and "Valid Until" timestamps. Freshly minted certificates (< 72 hours old) are a strong indicator of disposable phishing campaigns.'
        },
        {
          title: 'HSTS & Protocol Security',
          desc: 'Ensure HTTP Strict Transport Security (HSTS) headers are active to prevent SSL stripping attacks and unauthorized protocol downgrades.'
        }
      ],
      tips: 'Mismatches between the target hostname in the address bar and the Subject Common Name on the certificate indicate potential man-in-the-middle or spoofing activity.'
    },
    'redirect-traversal': {
      category: 'Routing & Traffic',
      badgeClass: 'badge-medium',
      icon: 'fas fa-route',
      readTime: '3 min read',
      title: 'Redirect Traversal, Cross-Domain Jumps & Loop Detection',
      summary: 'How attackers utilize URL shorteners, multi-hop redirect chains, and protocol downgrades to evade secure email gateways and conceal malicious destinations.',
      steps: [
        {
          title: 'Multi-Hop Sequential Tracing',
          desc: 'The engine traces up to 10 redirect hops sequentially, recording HTTP status codes (301, 302, 307, 308), latency per hop, and Location headers.'
        },
        {
          title: 'Cross-Domain Transition Highlights',
          desc: 'When a hop redirects traffic from one apex domain to an entirely distinct third-party domain, the visualizer node glows orange to alert analysts.'
        },
        {
          title: 'HTTPS-to-HTTP Protocol Downgrades',
          desc: 'If an encrypted HTTPS hop redirects to an unencrypted HTTP destination, the hop turns bright red, signaling that data is exposed to cleartext interception.'
        },
        {
          title: 'Circular Loop Detection',
          desc: 'The engine detects circular routing cycles (e.g., Hop 1 -> Hop 2 -> Hop 1) and halts execution safely, preventing socket exhaustion.'
        }
      ],
      tips: 'Click on any node in the Redirect Chain visualizer diagram to view expanded response headers, timestamps, and server details.'
    },
    'compliance': {
      category: 'Auditing & Compliance',
      badgeClass: 'badge-low',
      icon: 'fas fa-award',
      readTime: '3 min read',
      title: 'Compliance Standards: ISO 27001, SOC 2, GDPR & PDF Audits',
      summary: 'Conducting ethical cyber reconnaissance within global legal and regulatory frameworks, data privacy rules, and enterprise compliance standards.',
      steps: [
        {
          title: 'Authorized Scope & Rules of Engagement',
          desc: 'Ensure all domain and URL intelligence assessments adhere strictly to written authorization and ethical research guidelines.'
        },
        {
          title: 'Data Privacy & Local In-Memory Processing',
          desc: 'All URL analyses are performed in-memory on the local server. No user credentials, cookies, or personally identifiable data (PII) are stored or shared.'
        },
        {
          title: 'Executive PDF Audit Reports',
          desc: 'Generate signed, time-stamped ReportLab PDF assessments suitable for C-suite presentations, security compliance audits, and regulatory filings.'
        },
        {
          title: 'Framework Alignment (ISO 27001 / SOC 2 / NIST)',
          desc: 'Map identified vulnerabilities, redirect risks, and configuration drift to ISO 27001 Annex A controls and SOC 2 Type II criteria.'
        }
      ],
      tips: 'Maintain a verifiable chain of custody by generating and archiving executive PDF reports for all recurring domain assessments.'
    },
    '2fa': {
      category: 'Account Security',
      badgeClass: 'badge-low',
      icon: 'fas fa-user-shield',
      readTime: '3 min read',
      title: 'How to enable two-factor login',
      summary: 'Protect your account from credential stuffing and password reuse attacks using time-based one-time passwords (TOTP) or hardware security keys.',
      steps: [
        {
          title: 'Choose a strong Authenticator App',
          desc: 'Install an RFC 6238 compliant authenticator such as Google Authenticator, Bitwarden, Microsoft Authenticator, or 1Password on your mobile device.'
        },
        {
          title: 'Access Security Preferences',
          desc: 'Navigate to your Profile Settings > Security > Two-Factor Authentication (2FA) and select "Setup Authenticator App".'
        },
        {
          title: 'Scan the QR Code',
          desc: 'Open your authenticator app, tap "+" or "Add Account", and scan the encrypted QR code presented on your screen. Alternatively, copy the base32 secret key manually.'
        },
        {
          title: 'Verify 6-digit Code & Store Recovery Keys',
          desc: 'Input the current 6-digit verification code to confirm synchronization. Safely export and print your emergency recovery scratch codes in an offline vault.'
        }
      ],
      tips: 'Never share your 2FA codes. SMS-based 2FA is discouraged due to SIM swapping vulnerabilities; prefer app-based TOTP or FIDO2/WebAuthn hardware keys.'
    },
    'phishing': {
      category: 'Incident Response',
      badgeClass: 'badge-high',
      icon: 'fas fa-exclamation-triangle',
      readTime: '4 min read',
      title: 'Spot and report a phishing email',
      summary: 'Identify deceptive social engineering lures, analyze authentication headers, and report suspected malicious emails to security teams.',
      steps: [
        {
          title: 'Examine Sender & Display Name Alignment',
          desc: 'Attackers frequently spoof display names (e.g. "IT Support") while sending from lookalike domains (support-helpdesk.top). Always check the raw sender email.'
        },
        {
          title: 'Inspect Email Headers (SPF, DKIM, DMARC)',
          desc: 'Review RFC 5322 headers for SPF=pass, DKIM=pass, and DMARC=pass. A status of "softfail" or "none" with external source IPs signals deceptive spoofing.'
        },
        {
          title: 'Scrutinize Links Without Clicking',
          desc: 'Hover over hyperlinks to preview their actual destination URL. Look out for Punycode homoglyphs (xn--), raw IP addresses, and abnormal redirects.'
        },
        {
          title: 'Export & Report to Security / SOC',
          desc: 'Do not click or reply. Export the message as an .eml or .msg file with full RFC headers and forward it to your organization\'s incident response team.'
        }
      ],
      tips: 'Use our URL Intelligence Analyzer to evaluate any suspicious URLs or links found in suspicious emails before engaging.'
    },
    'vuln-score': {
      category: 'Scans & Reports',
      badgeClass: 'badge-medium',
      icon: 'fas fa-broadcast-tower',
      readTime: '3 min read',
      title: 'Understand your vulnerability score',
      summary: 'Learn how our passive threat scoring engine evaluates risk metrics, heuristic weights, and remediation priorities.',
      steps: [
        {
          title: 'Transparent Scoring Model',
          desc: 'Scores range from 0 to 100%. Low Risk is 0-30%, Medium Risk is 31-60%, and High Risk is 61-100%. The score is calculated based on triggered heuristic patterns.'
        },
        {
          title: 'Flag Contributions & Heuristic Weights',
          desc: 'Each triggered rule carries severity points: Raw IP as domain (+25 pts), Userinfo "@" deception (+20 pts), Punycode homoglyphs (+20 pts), Protocol Downgrade (+20 pts), and Suspicious TLDs (+10 pts).'
        },
        {
          title: 'Architecture & Redirect Telemetry',
          desc: 'Scrutinize the RFC URL structure table and the Redirect Chain Visualizer to identify which specific component is triggering threat heuristics.'
        },
        {
          title: 'Audit Documentation',
          desc: 'Download the comprehensive PDF report to share detailed technical breakdowns and remediation priorities with development and hosting teams.'
        }
      ],
      tips: 'A score of 0% indicates no known suspicious patterns were detected in the URL structure or redirect path, but defense-in-depth is always recommended.'
    },
    'data-breach': {
      category: 'Incident Response',
      badgeClass: 'badge-high',
      icon: 'fas fa-shield-virus',
      readTime: '5 min read',
      title: 'What to do after a data breach',
      summary: 'A standard 4-phase incident response playbook: Containment, Eradication, Notification, and Post-Mortem Hardening.',
      steps: [
        {
          title: 'Phase 1: Immediate Containment',
          desc: 'Isolate affected servers and subnets from the network. Revoke compromised API keys, database credentials, and active administrative sessions immediately.'
        },
        {
          title: 'Phase 2: Preserve Evidence & Forensic Logs',
          desc: 'Take volatile memory dumps and disk snapshots before rebooting. Secure firewall, web server access, and DNS query logs for forensic analysis.'
        },
        {
          title: 'Phase 3: Legal & Regulatory Notification',
          desc: 'Determine if personal data (PII) was exposed. Comply with GDPR (72-hour notification threshold), CCPA, or relevant jurisdictional disclosure laws.'
        },
        {
          title: 'Phase 4: Eradication & Long-Term Hardening',
          desc: 'Patch the root cause vulnerability, enforce mandatory password resets with MFA, rotate cryptographic certificates, and conduct a thorough post-incident audit.'
        }
      ],
      tips: 'If you suspect an active ongoing breach, click "Report an incident" to notify our emergency triage team immediately.'
    }
  };

  function initModernHelpCenter() {
    // 1. Article Modal Setup
    const articleModal = document.getElementById('helpArticleModal');
    const closeArticleModalBtn = document.getElementById('closeHelpArticleModalBtn');
    const closeArticleFooterBtn = document.getElementById('closeHelpArticleFooterBtn');
    const feedbackYesBtn = document.getElementById('helpFeedbackYesBtn');
    const feedbackNoBtn = document.getElementById('helpFeedbackNoBtn');

    function openArticle(articleId) {
      const art = HELP_ARTICLES[articleId];
      if (!art) {
        console.warn('Information guide not found for id:', articleId);
        showToast('Guide information not found for: ' + articleId, 'info');
        return;
      }
      if (!articleModal) return;

      const titleEl = document.getElementById('helpArticleModalTitle');
      const badgeEl = document.getElementById('helpArticleCategoryBadge');
      const timeEl = document.getElementById('helpArticleReadTime');
      const iconEl = document.getElementById('helpArticleModalBadge');
      const bodyEl = document.getElementById('helpArticleModalBody');

      if (titleEl) titleEl.textContent = art.title;
      if (badgeEl) {
        badgeEl.textContent = art.category;
        badgeEl.className = `badge ${art.badgeClass || 'badge-low'}`;
      }
      if (timeEl) timeEl.textContent = art.readTime;
      if (iconEl) iconEl.innerHTML = `<i class="${art.icon} neon-cyan"></i>`;

      if (bodyEl) {
        const stepsHtml = (art.steps || []).map((step, idx) => `
          <div class="article-step-item">
            <div class="article-step-number">${idx + 1}</div>
            <div class="article-step-body">
              <h5>${escapeHtml(step.title)}</h5>
              <p>${escapeHtml(step.desc)}</p>
            </div>
          </div>
        `).join('');

        bodyEl.innerHTML = `
          <p class="text-secondary mb-3" style="font-size: 0.93rem; line-height: 1.5;">${escapeHtml(art.summary)}</p>
          <div class="article-steps-list">${stepsHtml}</div>
          ${art.tips ? `<div class="article-tips-box"><i class="fas fa-lightbulb neon-yellow"></i> <strong>Pro Tip:</strong> ${escapeHtml(art.tips)}</div>` : ''}
        `;
      }

      // Explicitly reveal modal and prevent background scroll
      articleModal.classList.remove('hidden');
      articleModal.classList.add('show');
      articleModal.style.display = 'flex';
      document.body.style.overflow = 'hidden';
    }

    function closeArticle() {
      if (articleModal) {
        articleModal.classList.add('hidden');
        articleModal.classList.remove('show');
        articleModal.style.display = 'none';
      }
      document.body.style.overflow = '';
    }

    if (closeArticleModalBtn) closeArticleModalBtn.addEventListener('click', closeArticle);
    if (closeArticleFooterBtn) closeArticleFooterBtn.addEventListener('click', closeArticle);
    if (articleModal) {
      articleModal.addEventListener('click', (e) => {
        if (e.target === articleModal) closeArticle();
      });
    }

    if (feedbackYesBtn) {
      feedbackYesBtn.addEventListener('click', () => {
        showToast('Thank you for your feedback!', 'success');
      });
    }
    if (feedbackNoBtn) {
      feedbackNoBtn.addEventListener('click', () => {
        showToast('Feedback noted. We will improve this guide!', 'info');
      });
    }

    // 2. Wire Popular Article clicks
    document.querySelectorAll('.help-article-item').forEach(item => {
      const artId = item.getAttribute('data-article');
      item.addEventListener('click', () => openArticle(artId));
      item.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          openArticle(artId);
        }
      });
    });

    // 3. Wire Category Card clicks (all 8 cards)
    document.querySelectorAll('.help-cat-card').forEach(card => {
      const catId = card.getAttribute('data-cat');
      card.addEventListener('click', () => openArticle(catId));
      card.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          openArticle(catId);
        }
      });
    });

    // 4. Ticket & Contact Modal Setup
    const ticketModal = document.getElementById('helpTicketModal');
    const closeTicketModalBtn = document.getElementById('closeHelpTicketModalBtn');
    const cancelTicketModalBtn = document.getElementById('cancelHelpTicketModalBtn');
    const reportIncidentBtn = document.getElementById('reportIncidentBtn');
    const helpEmailSupportBtn = document.getElementById('helpEmailSupportBtn');
    const helpOpenTicketBtn = document.getElementById('helpOpenTicketBtn');

    function openTicketModal(config) {
      if (!ticketModal) return;
      const titleEl = document.getElementById('ticketModalTitle');
      const subEl = document.getElementById('ticketModalSubtitle');
      const badgeEl = document.getElementById('ticketModalBadge');
      const subjectInput = document.getElementById('contactSubject');
      const msgInput = document.getElementById('contactMessage');

      if (titleEl) titleEl.textContent = config.title || 'Submit Support Ticket';
      if (subEl) subEl.textContent = config.subtitle || 'Our response team will assist you';
      if (badgeEl) badgeEl.innerHTML = `<i class="${config.icon || 'fas fa-headset'} neon-cyan"></i>`;
      if (subjectInput && config.defaultSubject) subjectInput.value = config.defaultSubject;
      if (msgInput && config.defaultPlaceholder) msgInput.placeholder = config.defaultPlaceholder;

      ticketModal.classList.remove('hidden');
      ticketModal.classList.add('show');
      ticketModal.style.display = 'flex';
      document.body.style.overflow = 'hidden';

      const nameInput = document.getElementById('contactName');
      if (nameInput) nameInput.focus();
    }

    function closeTicketModal() {
      if (ticketModal) {
        ticketModal.classList.add('hidden');
        ticketModal.classList.remove('show');
        ticketModal.style.display = 'none';
      }
      document.body.style.overflow = '';
    }

    if (closeTicketModalBtn) closeTicketModalBtn.addEventListener('click', closeTicketModal);
    if (cancelTicketModalBtn) cancelTicketModalBtn.addEventListener('click', closeTicketModal);
    if (ticketModal) {
      ticketModal.addEventListener('click', (e) => {
        if (e.target === ticketModal) closeTicketModal();
      });
    }

    // Global Escape Key to close any active modal
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeArticle();
        closeTicketModal();
      }
    });

    if (reportIncidentBtn) {
      reportIncidentBtn.addEventListener('click', () => {
        openTicketModal({
          title: '🚨 Emergency Incident Response',
          subtitle: 'Active threat triage & incident response dispatch',
          icon: 'fas fa-exclamation-triangle text-red',
          defaultSubject: '[EMERGENCY INCIDENT] Active Security Threat Under Investigation',
          defaultPlaceholder: 'Please describe the incident: affected domains, observed attack indicators, unauthorized redirect activity, or compromise timeline...'
        });
      });
    }

    if (helpEmailSupportBtn) {
      helpEmailSupportBtn.addEventListener('click', () => {
        openTicketModal({
          title: '📧 Contact Cybersecurity Support',
          subtitle: 'Technical assistance, inquiries, and vulnerability disclosures',
          icon: 'far fa-envelope neon-cyan',
          defaultSubject: 'Support & Research Inquiry',
          defaultPlaceholder: 'Provide details about your question, observation, or platform inquiry (minimum 10 characters)...'
        });
      });
    }

    if (helpOpenTicketBtn) {
      helpOpenTicketBtn.addEventListener('click', () => {
        openTicketModal({
          title: '🎫 Open Support Ticket',
          subtitle: 'Platform ticket tracking & technical assistance',
          icon: 'far fa-clipboard neon-cyan',
          defaultSubject: 'Platform Support Ticket',
          defaultPlaceholder: 'Describe the issue or feature request in detail...'
        });
      });
    }

    // 5. Search & Filter
    const searchInput = document.getElementById('helpSearchInput');
    const tagPills = document.querySelectorAll('.help-tag-pill');

    function applySearchFilter(query) {
      const q = (query || '').toLowerCase().trim();

      // Filter Category Cards (all 8 cards)
      document.querySelectorAll('.help-cat-card').forEach(card => {
        const title = (card.querySelector('.help-cat-title')?.textContent || '').toLowerCase();
        const desc = (card.querySelector('.help-cat-desc')?.textContent || '').toLowerCase();
        const catKey = (card.getAttribute('data-cat') || '').toLowerCase();
        const artData = HELP_ARTICLES[catKey];
        const summary = artData ? (artData.summary || '').toLowerCase() : '';
        const matches = !q || title.includes(q) || desc.includes(q) || catKey.includes(q) || summary.includes(q);
        card.style.display = matches ? 'flex' : 'none';
      });

      // Filter Popular Articles
      document.querySelectorAll('.help-article-item').forEach(item => {
        const title = (item.querySelector('.help-article-title')?.textContent || '').toLowerCase();
        const artKey = (item.getAttribute('data-article') || '').toLowerCase();
        const artData = HELP_ARTICLES[artKey];
        const summary = artData ? (artData.summary || '').toLowerCase() : '';
        const matches = !q || title.includes(q) || artKey.includes(q) || summary.includes(q);
        item.style.display = matches ? 'flex' : 'none';
      });

      // Update Tag Pills active state
      tagPills.forEach(pill => {
        const pQuery = (pill.getAttribute('data-query') || '').toLowerCase();
        if (q && q.includes(pQuery)) {
          pill.classList.add('active');
        } else {
          pill.classList.remove('active');
        }
      });
    }

    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        applySearchFilter(e.target.value);
      });

      searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          const q = (searchInput.value || '').toLowerCase().trim();
          if (!q) return;
          // Look for direct article match
          for (const [key, art] of Object.entries(HELP_ARTICLES)) {
            if (art.title.toLowerCase().includes(q) || key.includes(q)) {
              openArticle(key);
              break;
            }
          }
        }
      });
    }

    tagPills.forEach(pill => {
      pill.addEventListener('click', () => {
        const q = pill.getAttribute('data-query') || '';
        if (searchInput) {
          if (searchInput.value.toLowerCase() === q.toLowerCase()) {
            searchInput.value = '';
            applySearchFilter('');
          } else {
            searchInput.value = q;
            applySearchFilter(q);
          }
        }
      });
    });
  }

  function initContactForm() {
    const form = document.getElementById('contactForm');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
      e.preventDefault();

      const nameInput = document.getElementById('contactName');
      const emailInput = document.getElementById('contactEmail');
      const subjectInput = document.getElementById('contactSubject');
      const messageInput = document.getElementById('contactMessage');
      const honeypotInput = document.getElementById('contactHoneypot');
      const submitBtn = document.getElementById('contactSubmitBtn');

      // Clear previous error styles
      document.querySelectorAll('.form-error').forEach(el => el.textContent = '');

      let isValid = true;
      if (!nameInput.value.trim()) {
        setText('contactNameError', 'Please provide your full name.');
        isValid = false;
      }
      if (!emailInput.value.trim() || !/^\S+@\S+\.\S+$/.test(emailInput.value)) {
        setText('contactEmailError', 'Please provide a valid email address.');
        isValid = false;
      }
      if (!subjectInput.value.trim()) {
        setText('contactSubjectError', 'Please provide a subject line.');
        isValid = false;
      }
      if (!messageInput.value.trim() || messageInput.value.trim().length < 10) {
        setText('contactMessageError', 'Message must be at least 10 characters long.');
        isValid = false;
      }

      if (!isValid) return;

      submitBtn.disabled = true;
      submitBtn.querySelector('.spinner')?.classList.remove('hidden');
      submitBtn.querySelector('.btn-text')?.classList.add('hidden');

      try {
        const response = await fetch('/api/contact', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: nameInput.value.trim(),
            email: emailInput.value.trim(),
            subject: subjectInput.value.trim(),
            message: messageInput.value.trim(),
            honeypot: honeypotInput ? honeypotInput.value : ''
          })
        });

        const data = await response.json();
        if (!response.ok || !data.success) {
          throw new Error(data.error || 'Failed to submit contact message');
        }

        showToast(data.message || 'Support request submitted successfully!', 'success');
        form.reset();
        document.getElementById('helpTicketModal')?.classList.add('hidden');
      } catch (err) {
        showToast(`Submission Error: ${err.message}`, 'error');
      } finally {
        submitBtn.disabled = false;
        submitBtn.querySelector('.spinner')?.classList.add('hidden');
        submitBtn.querySelector('.btn-text')?.classList.remove('hidden');
      }
    });
  }

  function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
      const tag = (e.target.tagName || '').toLowerCase();
      const isInput = tag === 'input' || tag === 'textarea' || tag === 'select';

      // Esc closes modals
      if (e.key === 'Escape') {
        document.querySelectorAll('.modal-backdrop').forEach(m => {
          m.classList.add('hidden');
          m.classList.remove('show');
          m.style.display = 'none';
        });
        document.body.style.overflow = '';
        return;
      }

      if (isInput) return;

      // '?' opens Help Center
      if (e.key === '?') {
        e.preventDefault();
        document.getElementById('help-section')?.scrollIntoView({ behavior: 'smooth' });
        showToast('Navigated to Help Center', 'info');
      }

      // 'Ctrl+K' focuses Search bar or URL input
      if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        const helpSearch = document.getElementById('helpSearchInput');
        const urlInput = document.getElementById('analyzerUrl');
        // If help section is in view or focused, focus helpSearch, else focus urlInput
        const helpSec = document.getElementById('help-section');
        const rect = helpSec ? helpSec.getBoundingClientRect() : null;
        if (rect && rect.top <= window.innerHeight && rect.bottom >= 0 && helpSearch) {
          helpSearch.focus();
          helpSearch.select();
        } else if (helpSearch) {
          helpSearch.focus();
          helpSearch.select();
        } else if (urlInput) {
          urlInput.focus();
          urlInput.select();
        }
      }


    });
  }

  /* ==========================================================================
     8. Utilities (Clipboard, Numbers, Toasts, Sanitization)
     ========================================================================== */
  function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
    } else {
      fallbackCopy(text);
    }
  }

  function fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
    } catch (e) {
      console.warn('Fallback copy failed', e);
    }
    document.body.removeChild(textarea);
  }

  function animateNumber(element, target) {
    if (!element) return;
    if (target === 0) {
      element.textContent = '0';
      return;
    }
    let current = 0;
    const duration = 1000;
    const stepTime = 20;
    const steps = duration / stepTime;
    const increment = target / steps;

    const timer = setInterval(() => {
      current += increment;
      if (current >= target) {
        element.textContent = Math.round(target);
        clearInterval(timer);
      } else {
        element.textContent = Math.round(current);
      }
    }, stepTime);
  }

  function showToast(message, type = 'info', duration = 3500) {
    if (!elements.toastStack) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let icon = 'fas fa-info-circle';
    if (type === 'success') icon = 'fas fa-check-circle';
    else if (type === 'error') icon = 'fas fa-exclamation-circle';

    toast.innerHTML = `
      <i class="${icon}"></i>
      <span>${escapeHtml(message)}</span>
    `;

    elements.toastStack.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function capitalize(str) {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

})();

