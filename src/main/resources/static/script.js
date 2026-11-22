/**
 * ProofVault — Digital Evidence Integrity and Verification System Client
 * Vanilla JavaScript — connected directly to Spring Boot REST API.
 *
 * Endpoints:
 * - POST /api/evidence/register       -> Multipart evidence intake & SHA-256 calculation
 * - POST /api/evidence/verify/{id}    -> Comparison file integrity verification
 * - GET  /api/evidence                -> Full evidence records list from MySQL
 * - GET  /api/evidence/{id}           -> Single record by ID or SHA-256 Hash
 * - GET  /api/audit                   -> Chronological audit log entries
 * - GET  /api/audit/verify            -> Cryptographic audit-chain validator
 */

// ============================================================================
// 1. APPLICATION STATE
// ============================================================================
const viewLabels = {
    overview: "Overview",
    register: "Register Evidence",
    verify:   "Verify Evidence",
    records:  "Evidence Records",
    audit:    "Audit Trail"
};

let currentEvidenceList = [];
let currentAuditList    = [];
let currentModalRecord  = null;

// ============================================================================
// 2. NAVIGATION
// ============================================================================
function navigateTo(viewName) {
    document.querySelectorAll(".view-section").forEach(sec => sec.classList.remove("active"));
    document.querySelectorAll(".nav-item").forEach(item => item.classList.remove("active"));

    const target = document.getElementById(`view-${viewName}`);
    if (target) target.classList.add("active");

    const btn = document.querySelector(`.nav-item[data-view="${viewName}"]`);
    if (btn) btn.classList.add("active");

    const crumb = document.getElementById("currentViewLabel");
    if (crumb && viewLabels[viewName]) crumb.textContent = viewLabels[viewName];

    closeModal();
    closeMobileSidebar();

    if (viewName === "overview" || viewName === "records" || viewName === "audit") {
        refreshVaultData();
    }
}

function toggleSidebar() {
    const sidebar = document.getElementById("sidebar");
    if (!sidebar) return;
    sidebar.classList.toggle("mobile-open");
}

function closeMobileSidebar() {
    const sidebar = document.getElementById("sidebar");
    if (sidebar) sidebar.classList.remove("mobile-open");
}

// ============================================================================
// 3. TOAST NOTIFICATIONS
// ============================================================================
let toastTimer = null;

function showToast(message, isError = false) {
    const toast     = document.getElementById("toastNotification");
    const msgEl     = document.getElementById("toastMessage");
    const indicator = toast && toast.querySelector(".toast-indicator");
    if (!toast || !msgEl) return;

    msgEl.textContent = message;
    if (indicator) {
        indicator.style.backgroundColor = isError
            ? "var(--status-red)"
            : "var(--status-green)";
    }
    toast.classList.remove("hidden");

    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.add("hidden"), 4000);
}

// ============================================================================
// 4. CLIPBOARD COPY
// ============================================================================
function copyHash(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const text = el.textContent.trim();
    if (!text || text === "—") return;

    copyHashText(text);
}

function copyHashText(text) {
    if (!text || text === "—") return;

    navigator.clipboard.writeText(text).then(() => {
        showToast("Copied to clipboard.");
    }).catch(() => {
        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
        showToast("Copied to clipboard.");
    });
}

// ============================================================================
// 5. BACKEND DATA FETCH
// ============================================================================
async function refreshVaultData() {
    try {
        const [evidenceRes, auditRes] = await Promise.all([
            fetch('/api/evidence'),
            fetch('/api/audit')
        ]);

        if (evidenceRes.ok) {
            currentEvidenceList = await evidenceRes.json();
            renderEvidenceRecords();
            renderOverviewEvidence();
            updateDashboardMetrics();
        }

        if (auditRes.ok) {
            currentAuditList = await auditRes.json();
            renderAuditLogs();
            renderOverviewActivities();
        }

        // Live status indicator in topbar
        const badge     = document.getElementById("dataModeBadge");
        const badgeText = document.querySelector("#dataModeBadge .mode-text");
        const modePulse = document.querySelector("#dataModeBadge .mode-pulse");

        if (badge)     badge.classList.add("live");
        if (modePulse) modePulse.style.backgroundColor = "var(--status-green)";
        if (badgeText) {
            const n = currentEvidenceList.length;
            badgeText.textContent = `VAULT CONNECTED — ${n} EVIDENCE ITEM${n !== 1 ? "S" : ""}`;
            badgeText.style.color = "var(--status-green)";
        }

    } catch (err) {
        console.error("Failed to fetch ProofVault data:", err);
    }
}

// ============================================================================
// 6. DASHBOARD METRICS
// ============================================================================
function updateDashboardMetrics() {
    const totalEl    = document.getElementById("metricTotal");
    const verifiedEl = document.getElementById("metricVerified");
    const tamperedEl = document.getElementById("metricTampered");
    const pendingEl  = document.getElementById("metricPending");

    const totalCount = currentEvidenceList.length;
    let verifiedCount = 0;
    let tamperedCount = 0;
    let pendingCount = 0;

    currentEvidenceList.forEach(rec => {
        const status = getLastVerificationStatus(rec.evidenceId);
        if (status === "VERIFIED") {
            verifiedCount++;
        } else if (status === "TAMPERED") {
            tamperedCount++;
        } else {
            pendingCount++;
        }
    });

    animateCount(totalEl,    totalCount);
    animateCount(verifiedEl, verifiedCount);
    animateCount(tamperedEl, tamperedCount);
    animateCount(pendingEl,  pendingCount);
}

function animateCount(el, target) {
    if (!el) return;
    const start = parseInt(el.textContent) || 0;
    if (start === target) {
        el.textContent = target;
        return;
    }
    const duration = 280;
    const startTs  = performance.now();

    function step(ts) {
        const progress = Math.min((ts - startTs) / duration, 1);
        const eased    = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(start + (target - start) * eased);
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

// ============================================================================
// 7. STATUS BADGES & HELPERS
// ============================================================================
function formatStatusBadge(status) {
    if (status === "VERIFIED") {
        return `<span class="badge badge-success">&#10003; VERIFIED</span>`;
    } else if (status === "TAMPERED") {
        return `<span class="badge badge-danger">&#9888; TAMPERED</span>`;
    }
    return `<span class="badge badge-amber">&#8226; RECORDED</span>`;
}

function getLastVerificationStatus(evidenceId) {
    for (const log of currentAuditList) {
        if (log.evidenceId === evidenceId && log.action === "INTEGRITY_CHECK") {
            if (log.result && log.result.includes("PASSED")) return "VERIFIED";
            if (log.result && log.result.includes("FAILED")) return "TAMPERED";
        }
    }
    return "RECORDED";
}

function formatActionBadge(action) {
    const labels = {
        EVIDENCE_REGISTER:    "REGISTERED",
        INTEGRITY_CHECK:      "INTEGRITY CHECK",
        EVIDENCE_MISSING:     "NOT FOUND",
        INVALID_UPLOAD:       "REJECTED"
    };
    return escapeHtml(labels[action] || action);
}

// ============================================================================
// 8. OVERVIEW TABLES RENDERING
// ============================================================================
function renderOverviewEvidence() {
    const tbody = document.getElementById("overviewEvidenceBody");
    if (!tbody) return;

    if (!currentEvidenceList || currentEvidenceList.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5" class="empty-cell">
                    <div class="empty-state">
                        <p class="empty-text">No digital evidence deposited in vault</p>
                        <button type="button" class="btn btn-primary btn-sm mt-3" onclick="navigateTo('register')">
                            Register First Evidence
                        </button>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = currentEvidenceList.slice(0, 5).map(rec => {
        const status = getLastVerificationStatus(rec.evidenceId);
        return `
            <tr>
                <td class="font-mono text-accent" style="font-size:0.8rem; font-weight:600;">${escapeHtml(rec.evidenceId)}</td>
                <td><strong style="font-size:0.84rem;">${escapeHtml(rec.fileName)}</strong></td>
                <td><span class="badge badge-subtle">${escapeHtml(rec.category)}</span></td>
                <td>${escapeHtml(rec.investigator || "—")}</td>
                <td>${formatStatusBadge(status)}</td>
            </tr>
        `;
    }).join("");
}

function renderOverviewActivities() {
    const tbody = document.getElementById("overviewActivityBody");
    if (!tbody) return;

    if (!currentAuditList || currentAuditList.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5" class="empty-cell">
                    <div class="empty-state">
                        <p class="empty-text">No audit activities recorded</p>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = currentAuditList.slice(0, 5).map(log => {
        const isPass   = log.result && log.result.includes("PASSED");
        const isFail   = log.result && log.result.includes("FAILED");
        const resClass = isFail ? "text-red" : isPass ? "text-green" : "text-muted";
        return `
            <tr>
                <td class="font-mono" style="font-size:0.78rem;">${formatDate(log.timestamp)}</td>
                <td><span class="badge badge-subtle">${formatActionBadge(log.action)}</span></td>
                <td class="font-mono text-accent" style="font-size:0.8rem; font-weight:600;">${escapeHtml(log.evidenceId)}</td>
                <td>${escapeHtml(log.investigatorName || "System")}</td>
                <td><span class="font-mono ${resClass}" style="font-size:0.78rem;">${escapeHtml(log.result)}</span></td>
            </tr>
        `;
    }).join("");
}

// ============================================================================
// 9. EVIDENCE RECORDS TABLE & FILTERING
// ============================================================================
let searchTimer = null;

function renderEvidenceRecords() {
    const tbody          = document.getElementById("evidenceRecordsTableBody");
    const countText      = document.getElementById("recordsCountText");
    const searchInput    = document.getElementById("recordsSearchInput");
    const categoryFilter = document.getElementById("recordsCategoryFilter");
    const statusFilter   = document.getElementById("recordsStatusFilter");
    if (!tbody) return;

    if (currentEvidenceList.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="empty-cell">
                    <div class="empty-state">
                        <svg viewBox="0 0 24 24" width="32" height="32" fill="none" stroke="currentColor" stroke-width="1.5" class="empty-icon">
                            <ellipse cx="12" cy="5" rx="9" ry="3"/>
                            <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
                            <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
                        </svg>
                        <p class="empty-text">No evidence records in vault</p>
                        <button type="button" class="btn btn-primary btn-sm mt-3" onclick="navigateTo('register')">
                            Register First Evidence
                        </button>
                    </div>
                </td>
            </tr>
        `;
        if (countText) countText.textContent = "0 evidence records";
        return;
    }

    const query   = searchInput ? searchInput.value.toLowerCase().trim() : "";
    const catVal  = categoryFilter ? categoryFilter.value.toUpperCase() : "";
    const statVal = statusFilter ? statusFilter.value.toUpperCase() : "";

    let filtered = currentEvidenceList;

    if (query) {
        filtered = filtered.filter(rec =>
            (rec.evidenceId   && rec.evidenceId.toLowerCase().includes(query))   ||
            (rec.fileName     && rec.fileName.toLowerCase().includes(query))     ||
            (rec.category     && rec.category.toLowerCase().includes(query))     ||
            (rec.investigator && rec.investigator.toLowerCase().includes(query)) ||
            (rec.sha256Hash   && rec.sha256Hash.toLowerCase().includes(query))
        );
    }

    if (catVal) {
        filtered = filtered.filter(rec => rec.category && rec.category.toUpperCase() === catVal);
    }

    if (statVal) {
        filtered = filtered.filter(rec => {
            const status = getLastVerificationStatus(rec.evidenceId);
            return status === statVal;
        });
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="empty-cell">
                    <p class="empty-text">No evidence records matching current search or filters</p>
                </td>
            </tr>
        `;
        if (countText) countText.textContent = `0 of ${currentEvidenceList.length} records match`;
        return;
    }

    tbody.innerHTML = filtered.map(rec => {
        const status    = getLastVerificationStatus(rec.evidenceId);
        const shortHash = rec.sha256Hash ? rec.sha256Hash.substring(0, 14) + "…" : "—";
        return `
            <tr>
                <td class="font-mono text-accent" style="font-size:0.78rem; font-weight:600;">${escapeHtml(rec.evidenceId)}</td>
                <td><strong style="font-size:0.85rem;">${escapeHtml(rec.fileName)}</strong></td>
                <td><span class="badge badge-subtle">${escapeHtml(rec.category)}</span></td>
                <td class="font-mono" style="font-size:0.78rem;">${rec.fileSizeFormatted || "0 B"}</td>
                <td>
                    <code class="hash-val" style="cursor:pointer;"
                          onclick="copyHashText('${escapeHtml(rec.sha256Hash)}')"
                          title="Click to copy full SHA-256 hash">${shortHash}</code>
                </td>
                <td class="font-mono" style="font-size:0.78rem;">${formatDate(rec.registrationTime)}</td>
                <td>${formatStatusBadge(status)}</td>
                <td>
                    <button type="button" class="btn-row-action" onclick="openEvidenceModal('${escapeHtml(rec.evidenceId)}')" title="View details">
                        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                        </svg>
                    </button>
                </td>
            </tr>
        `;
    }).join("");

    if (countText) {
        const isFiltered = query || catVal || statVal;
        countText.textContent = isFiltered
            ? `${filtered.length} of ${currentEvidenceList.length} records match`
            : `${filtered.length} evidence record${filtered.length !== 1 ? "s" : ""}`;
    }
}

// ============================================================================
// 10. AUDIT TRAIL TABLE & CHAIN CHECK
// ============================================================================
function renderAuditLogs(filterQuery = "") {
    const tbody     = document.getElementById("auditLogsTableBody");
    const countText = document.getElementById("auditCountText");
    if (!tbody) return;

    if (currentAuditList.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="empty-cell">
                    <div class="empty-state">
                        <svg viewBox="0 0 24 24" width="32" height="32" fill="none" stroke="currentColor" stroke-width="1.5" class="empty-icon">
                            <path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/>
                        </svg>
                        <p class="empty-text">No audit entries recorded</p>
                    </div>
                </td>
            </tr>
        `;
        if (countText) countText.textContent = "0 audit activities";
        return;
    }

    const query    = filterQuery.toLowerCase().trim();
    const filtered = query
        ? currentAuditList.filter(log =>
            (log.logId          && String(log.logId).includes(query))                     ||
            (log.evidenceId     && log.evidenceId.toLowerCase().includes(query))          ||
            (log.action         && log.action.toLowerCase().includes(query))              ||
            (log.investigatorName && log.investigatorName.toLowerCase().includes(query)) ||
            (log.result         && log.result.toLowerCase().includes(query))
          )
        : currentAuditList;

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="empty-cell">
                    <p class="empty-text">No audit logs matching "${escapeHtml(filterQuery)}"</p>
                </td>
            </tr>
        `;
        if (countText) countText.textContent = `0 of ${currentAuditList.length} logs match`;
        return;
    }

    tbody.innerHTML = filtered.map(log => {
        const isPass   = log.result && log.result.includes("PASSED");
        const isFail   = log.result && log.result.includes("FAILED");
        const resClass = isFail ? "text-red" : isPass ? "text-green" : "text-muted";
        return `
            <tr>
                <td class="font-mono" style="font-size:0.78rem; color:var(--text-secondary);">${log.logId}</td>
                <td><span class="badge badge-subtle">${formatActionBadge(log.action)}</span></td>
                <td class="font-mono text-accent" style="font-size:0.8rem; font-weight:600;">${escapeHtml(log.evidenceId)}</td>
                <td>${escapeHtml(log.investigatorName || "System")}</td>
                <td class="font-mono" style="font-size:0.78rem;">${formatDate(log.timestamp)}</td>
                <td><span class="font-mono ${resClass}" style="font-size:0.78rem;">${escapeHtml(log.result)}</span></td>
            </tr>
        `;
    }).join("");

    if (countText) {
        countText.textContent = query
            ? `${filtered.length} of ${currentAuditList.length} logs match`
            : `${filtered.length} audit activit${filtered.length !== 1 ? "ies" : "y"}`;
    }
}

async function checkAuditChain() {
    const banner = document.getElementById("chainStatusBanner");
    if (!banner) return;

    try {
        const res = await fetch("/api/audit/verify");
        const data = await res.json();

        banner.classList.remove("hidden");
        if (data.chainStatus === "INTACT") {
            banner.className = "alert-box alert-info mb-4";
            banner.innerHTML = `
                <div class="alert-icon-row">
                    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                    <div class="alert-title text-green">Audit Chain Verified Intact</div>
                </div>
                <div class="alert-body">
                    All ${data.totalEntries} sequential audit logs are cryptographically linked. Zero record alterations or deletions detected.
                </div>
            `;
            showToast("Audit chain verified intact.");
        } else if (data.chainStatus === "EMPTY") {
            banner.className = "alert-box alert-info mb-4";
            banner.innerHTML = `
                <div class="alert-title">Audit Trail Empty</div>
                <div class="alert-body">No audit records deposited yet.</div>
            `;
        } else {
            banner.className = "alert-box alert-danger mb-4";
            banner.innerHTML = `
                <div class="alert-icon-row">
                    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    <div class="alert-title text-red">Audit Chain Tamper Alert</div>
                </div>
                <div class="alert-body">
                    Chain linkage broken at Log #${data.tamperedLogId}: ${escapeHtml(data.reason)}
                </div>
            `;
            showToast("Chain verification failed: Tamper detected", true);
        }
    } catch (err) {
        console.error("Chain verification error:", err);
        showToast("Failed to verify audit chain: " + err.message, true);
    }
}

// ============================================================================
// 11. EVIDENCE DETAIL MODAL
// ============================================================================
function openEvidenceModal(evidenceId) {
    const rec = currentEvidenceList.find(r => r.evidenceId === evidenceId);
    if (!rec) return;
    currentModalRecord = rec;

    const status = getLastVerificationStatus(rec.evidenceId);

    setText("modalEvidenceTitle", rec.fileName);
    setText("modalEvidenceId",    rec.evidenceId);
    setText("modalCategory",      rec.category);
    setText("modalFileSize",      rec.fileSizeFormatted || "—");
    setText("modalInvestigator",  rec.investigator || "—");
    setText("modalRegistered",    formatDate(rec.registrationTime));
    setText("modalHash",          rec.sha256Hash || "—");

    const statusEl = document.getElementById("modalStatus");
    if (statusEl) statusEl.innerHTML = formatStatusBadge(status);

    const modal = document.getElementById("evidenceModal");
    if (modal) modal.classList.remove("hidden");
    document.body.style.overflow = "hidden";
}

function closeModal() {
    const modal = document.getElementById("evidenceModal");
    if (modal) modal.classList.add("hidden");
    document.body.style.overflow = "";
    currentModalRecord = null;
}

function prefillVerify() {
    if (!currentModalRecord) return;
    const idToVerify = currentModalRecord.evidenceId;
    closeModal();
    quickVerify(idToVerify);
}

function quickVerify(evidenceId) {
    navigateTo("verify");
    const idInput = document.getElementById("verifyEvidenceId");
    if (idInput) {
        idInput.value = evidenceId;
        idInput.focus();
    }
}

function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text || "—";
}

// ============================================================================
// 12. FILE UPLOAD DRAG-AND-DROP SETUP
// ============================================================================
function setupFileUploadZone(zoneId, inputId, detailsId, nameId, sizeId, clearBtnId) {
    const zone     = document.getElementById(zoneId);
    const input    = document.getElementById(inputId);
    const details  = document.getElementById(detailsId);
    const nameEl   = document.getElementById(nameId);
    const sizeEl   = document.getElementById(sizeId);
    const clearBtn = document.getElementById(clearBtnId);

    if (!zone || !input) return;

    zone.addEventListener("click", e => {
        if (e.target.tagName !== "INPUT" && e.target.tagName !== "BUTTON" && e.target.tagName !== "LABEL") {
            input.click();
        }
    });

    ["dragenter", "dragover"].forEach(evt => {
        zone.addEventListener(evt, e => {
            e.preventDefault();
            e.stopPropagation();
            zone.classList.add("dragover");
        });
    });

    ["dragleave", "drop"].forEach(evt => {
        zone.addEventListener(evt, e => {
            e.preventDefault();
            e.stopPropagation();
            zone.classList.remove("dragover");
        });
    });

    zone.addEventListener("drop", e => {
        const files = e.dataTransfer.files;
        if (files && files.length > 0) {
            input.files = files;
            displayFileInfo(files[0]);
        }
    });

    input.addEventListener("change", () => {
        if (input.files && input.files.length > 0) {
            displayFileInfo(input.files[0]);
        }
    });

    function displayFileInfo(file) {
        if (!file) return;
        if (nameEl) nameEl.textContent = file.name;
        if (sizeEl) sizeEl.textContent = formatBytes(file.size);
        if (details) details.classList.remove("hidden");
        zone.classList.add("has-file");
    }

    if (clearBtn) {
        clearBtn.addEventListener("click", e => {
            e.stopPropagation();
            input.value = "";
            if (details) details.classList.add("hidden");
            zone.classList.remove("has-file");
        });
    }
}

// ============================================================================
// 13. REGISTRATION FORM
// ============================================================================
function initRegisterForm() {
    const form          = document.getElementById("registerForm");
    const fileInput     = document.getElementById("registerFileInput");
    const investigator  = document.getElementById("investigatorName");
    const category      = document.getElementById("evidenceCategory");
    const notes         = document.getElementById("evidenceNotes");
    const submitBtn     = document.getElementById("btnRegisterSubmit");
    const fileError     = document.getElementById("registerFileError");
    const invError      = document.getElementById("investigatorError");
    const catError      = document.getElementById("categoryError");
    const feedback      = document.getElementById("registerFeedback");

    if (!form) return;

    form.addEventListener("submit", async e => {
        e.preventDefault();

        fileError.classList.add("hidden");
        invError.classList.add("hidden");
        catError.classList.add("hidden");
        if (feedback) feedback.classList.add("hidden");

        let valid = true;
        if (!fileInput.files || fileInput.files.length === 0) {
            fileError.classList.remove("hidden"); valid = false;
        }
        if (!investigator.value.trim()) {
            invError.classList.remove("hidden"); valid = false;
        }
        if (!category.value) {
            catError.classList.remove("hidden"); valid = false;
        }
        if (!valid) return;

        const fd = new FormData();
        fd.append("file", fileInput.files[0]);
        fd.append("investigator", investigator.value.trim());
        fd.append("category", category.value);
        if (notes && notes.value.trim()) {
            fd.append("notes", notes.value.trim());
        }

        const originalBtnHtml = submitBtn.innerHTML;
        submitBtn.disabled    = true;
        submitBtn.innerHTML   = `<svg class="spin-icon" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg><span>Depositing…</span>`;

        try {
            const res  = await fetch("/api/evidence/register", { method: "POST", body: fd });
            const data = await res.json();

            if (!res.ok) throw new Error(data.error || "Evidence registration failed.");

            // Show clean success feedback with prominent Evidence ID and quick-verify button
            feedback.className = "alert-box alert-info";
            feedback.innerHTML = `
                <div class="alert-icon-row">
                    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                    <div class="alert-title">Evidence Anchored Successfully</div>
                </div>
                <div class="alert-body">
                    <p style="margin-bottom:0.5rem;">File <strong>${escapeHtml(data.fileName)}</strong> deposited into vault.</p>
                    <div style="background:var(--bg-subtle); border:1px solid var(--border-color); padding:8px 10px; border-radius:4px; margin-bottom:8px; display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <span style="font-size:10px; color:var(--text-secondary); display:block; text-transform:uppercase; letter-spacing:0.04em;">Evidence ID</span>
                            <span class="font-mono text-accent" style="font-size:13px; font-weight:600;">${escapeHtml(data.evidenceId)}</span>
                        </div>
                        <button type="button" class="btn btn-secondary-subtle btn-sm" onclick="copyHashText('${escapeHtml(data.evidenceId)}')" title="Copy Evidence ID">
                            Copy ID
                        </button>
                    </div>
                    <div style="font-size:11.5px; color:var(--text-secondary); margin-bottom:10px;">
                        <span style="display:block; text-transform:uppercase; letter-spacing:0.04em; font-size:10px; margin-bottom:2px;">SHA-256 Digest:</span>
                        <code style="font-size:11px; word-break:break-all; cursor:pointer;"
                              onclick="copyHashText('${escapeHtml(data.sha256Hash)}')"
                              title="Click to copy hash">${escapeHtml(data.sha256Hash)}</code>
                    </div>
                    <button type="button" class="btn btn-verify btn-sm" onclick="quickVerify('${escapeHtml(data.evidenceId)}')" style="width:100%; justify-content:center;">
                        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                        Verify this file now &rarr;
                    </button>
                </div>
            `;
            feedback.classList.remove("hidden");

            showToast(`${data.evidenceId} registered.`);

            form.reset();
            const regDetails = document.getElementById("registerFileDetails");
            if (regDetails) regDetails.classList.add("hidden");
            const dropZone = document.getElementById("registerDropZone");
            if (dropZone) dropZone.classList.remove("has-file");

            await refreshVaultData();

        } catch (err) {
            console.error("Registration error:", err);
            feedback.className = "alert-box alert-danger";
            feedback.innerHTML = `
                <div class="alert-icon-row">
                    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    <div class="alert-title">Registration Failed</div>
                </div>
                <div class="alert-body">${escapeHtml(err.message)}</div>
            `;
            feedback.classList.remove("hidden");
            showToast(err.message, true);
        } finally {
            submitBtn.disabled  = false;
            submitBtn.innerHTML = originalBtnHtml;
        }
    });

    const resetBtn = document.getElementById("btnRegisterReset");
    if (resetBtn) {
        resetBtn.addEventListener("click", () => {
            fileError.classList.add("hidden");
            invError.classList.add("hidden");
            catError.classList.add("hidden");
            if (feedback) feedback.classList.add("hidden");
            const regDetails = document.getElementById("registerFileDetails");
            if (regDetails) regDetails.classList.add("hidden");
            const dropZone = document.getElementById("registerDropZone");
            if (dropZone) dropZone.classList.remove("has-file");
        });
    }
}

// ============================================================================
// 14. VERIFICATION FORM
// ============================================================================
function initVerifyForm() {
    const form        = document.getElementById("verifyForm");
    const idInput     = document.getElementById("verifyEvidenceId");
    const fileInput   = document.getElementById("verifyFileInput");
    const submitBtn   = document.getElementById("btnVerifySubmit");
    const idError     = document.getElementById("verifyIdError");
    const fileError   = document.getElementById("verifyFileError");
    const placeholder = document.getElementById("verifyStatePlaceholder");
    const stateOk     = document.getElementById("verifyStateSuccess");
    const stateBad    = document.getElementById("verifyStateTampered");

    if (!form) return;

    function resetCards() {
        [placeholder, stateOk, stateBad].forEach(el => el && el.classList.add("hidden"));
    }

    form.addEventListener("submit", async e => {
        e.preventDefault();
        let valid = true;

        idError.classList.add("hidden");
        fileError.classList.add("hidden");

        const evidenceId = idInput.value.trim();
        if (!evidenceId) { idError.classList.remove("hidden");   valid = false; }
        if (!fileInput.files || fileInput.files.length === 0) {
            fileError.classList.remove("hidden"); valid = false;
        }
        if (!valid) return;

        const fd = new FormData();
        fd.append("file", fileInput.files[0]);

        const originalBtnHtml = submitBtn.innerHTML;
        submitBtn.disabled    = true;
        submitBtn.innerHTML   = `<svg class="spin-icon" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg><span>Verifying…</span>`;

        try {
            const res  = await fetch(`/api/evidence/verify/${encodeURIComponent(evidenceId)}`, { method: "POST", body: fd });
            const data = await res.json();

            if (!res.ok) throw new Error(data.error || "Verification failed.");

            resetCards();

            if (data.status === "VERIFIED") {
                stateOk && stateOk.classList.remove("hidden");
                setText("resSuccessTime",       formatDate(data.timestamp));
                setText("resSuccessVaultHash",  data.vaultHash);
                setText("resSuccessTargetHash", data.candidateHash);
                showToast(`Integrity VERIFIED — ${data.evidenceId}`);
            } else {
                stateBad && stateBad.classList.remove("hidden");
                setText("resTamperTime",       formatDate(data.timestamp));
                setText("resTamperVaultHash",  data.vaultHash);
                setText("resTamperTargetHash", data.candidateHash);
                showToast(`TAMPER ALERT: Checksum mismatch for ${data.evidenceId}`, true);
            }

            await refreshVaultData();

        } catch (err) {
            console.error("Verification error:", err);
            showToast(err.message, true);
            resetCards();
            if (placeholder) {
                placeholder.classList.remove("hidden");
                placeholder.querySelector("h4") && (placeholder.querySelector("h4").textContent = "Verification failed");
                placeholder.querySelector("p")  && (placeholder.querySelector("p").textContent  = err.message);
            }
        } finally {
            submitBtn.disabled  = false;
            submitBtn.innerHTML = originalBtnHtml;
        }
    });
}

// ============================================================================
// 15. UTILITIES
// ============================================================================
function escapeHtml(str) {
    if (str == null) return "";
    return String(str)
        .replace(/&/g,  "&amp;")
        .replace(/</g,  "&lt;")
        .replace(/>/g,  "&gt;")
        .replace(/"/g,  "&quot;")
        .replace(/'/g,  "&#039;");
}

function formatDate(isoStr) {
    if (!isoStr) return "—";
    try {
        const d = new Date(isoStr);
        if (isNaN(d.getTime())) return isoStr;
        return d.toLocaleString(undefined, {
            year: "numeric", month: "short", day: "2-digit",
            hour: "2-digit", minute: "2-digit"
        });
    } catch {
        return isoStr;
    }
}

function formatBytes(bytes) {
    if (bytes == null) return "—";
    if (bytes < 1024)        return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}

// Injected CSS spinner keyframes
(function injectSpinnerCSS() {
    const style = document.createElement("style");
    style.textContent = `
        @keyframes spin { to { transform: rotate(360deg); } }
        .spin-icon { animation: spin 0.8s linear infinite; }
    `;
    document.head.appendChild(style);
})();

// ============================================================================
// 16. DOM READY INITIALIZATION
// ============================================================================
document.addEventListener("DOMContentLoaded", () => {
    // Nav items
    document.querySelectorAll(".nav-item").forEach(btn => {
        btn.addEventListener("click", () => {
            const view = btn.getAttribute("data-view");
            if (view) navigateTo(view);
        });
    });

    // Mobile sidebar toggle
    const toggleBtn = document.getElementById("sidebarToggle");
    if (toggleBtn) toggleBtn.addEventListener("click", toggleSidebar);

    document.addEventListener("click", e => {
        const sidebar = document.getElementById("sidebar");
        const toggle  = document.getElementById("sidebarToggle");
        if (sidebar && sidebar.classList.contains("mobile-open") &&
            !sidebar.contains(e.target) && e.target !== toggle && !toggle.contains(e.target)) {
            closeMobileSidebar();
        }
    });

    // Modal close handlers
    const modalClose    = document.getElementById("modalClose");
    const modalCloseBtn = document.getElementById("modalCloseBtn");
    const modalBackdrop = document.getElementById("evidenceModal");

    if (modalClose)    modalClose.addEventListener("click", closeModal);
    if (modalCloseBtn) modalCloseBtn.addEventListener("click", closeModal);
    if (modalBackdrop) {
        modalBackdrop.addEventListener("click", e => {
            if (e.target === modalBackdrop) closeModal();
        });
    }

    document.addEventListener("keydown", e => {
        if (e.key === "Escape") closeModal();
    });

    // File upload drag-and-drop
    setupFileUploadZone("registerDropZone", "registerFileInput", "registerFileDetails", "regFileName", "regFileSize", "regRemoveFile");
    setupFileUploadZone("verifyDropZone",   "verifyFileInput",   "verifyFileDetails",   "verFileName", "verFileSize", "verRemoveFile");

    // Forms
    initRegisterForm();
    initVerifyForm();

    // Evidence Records search & filters
    const recordsSearch   = document.getElementById("recordsSearchInput");
    const categoryFilter  = document.getElementById("recordsCategoryFilter");
    const statusFilter    = document.getElementById("recordsStatusFilter");

    if (recordsSearch) {
        recordsSearch.addEventListener("input", () => {
            clearTimeout(searchTimer);
            searchTimer = setTimeout(() => renderEvidenceRecords(), 140);
        });
    }
    if (categoryFilter) categoryFilter.addEventListener("change", () => renderEvidenceRecords());
    if (statusFilter)   statusFilter.addEventListener("change", () => renderEvidenceRecords());

    // Audit logs search
    const auditSearch = document.getElementById("auditSearchInput");
    if (auditSearch) {
        auditSearch.addEventListener("input", e => {
            clearTimeout(searchTimer);
            searchTimer = setTimeout(() => renderAuditLogs(e.target.value), 140);
        });
    }

    // Initial data fetch
    refreshVaultData();
    console.log("ProofVault: Light theme initialized.");
});
