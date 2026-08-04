"use strict";

document.addEventListener("DOMContentLoaded", () => {
  if (window.htmx) {
    window.htmx.config.historyCacheSize = 0;
    window.htmx.config.allowEval = false;
    window.htmx.config.allowScriptTags = false;
    window.htmx.config.selfRequestsOnly = true;
  }

  const moduleWeights = [...document.querySelectorAll("[data-module-weight]")];
  const moduleTotal = document.getElementById("module-weight-total");
  const moduleTotalMessage = document.querySelector("[data-module-total-message]");
  function updateModuleTotal() {
    if (!moduleWeights.length || !moduleTotal) return;
    const total = moduleWeights.reduce(
      (sum, input) => sum + (Number.parseFloat(input.value) || 0),
      0
    );
    moduleTotal.textContent = total.toFixed(3).replace(/\.?0+$/, "");
    const valid = Math.abs(total - 100) <= 0.001;
    moduleTotalMessage?.classList.toggle("invalid", !valid);
    moduleWeights[0].setCustomValidity(
      valid ? "" : "Module weights must total 100%."
    );
  }
  moduleWeights.forEach((input) => input.addEventListener("input", updateModuleTotal));
  updateModuleTotal();

  const scoringMode = document.getElementById("scoring-mode");
  const detectionWeight = document.getElementById("detection-weight");
  const blockingWeight = document.getElementById("blocking-weight");
  const scoringTotal = document.getElementById("scoring-weight-total");
  const scoringTotalMessage = document.querySelector("[data-scoring-total-message]");
  const scoringHelp = document.getElementById("scoring-mode-help");

  function updateScoringTotal() {
    if (!detectionWeight || !blockingWeight || !scoringTotal) return;
    const total =
      (Number.parseFloat(detectionWeight.value) || 0) +
      (Number.parseFloat(blockingWeight.value) || 0);
    scoringTotal.textContent = total.toFixed(3).replace(/\.?0+$/, "");
    const custom = scoringMode?.value === "custom";
    const valid = !custom || Math.abs(total - 100) <= 0.001;
    scoringTotalMessage?.classList.toggle("invalid", !valid);
    detectionWeight.setCustomValidity(
      valid ? "" : "Detection and blocking weights must total 100%."
    );
  }

  function configureScoringMode() {
    if (!scoringMode || !detectionWeight || !blockingWeight) return;
    const mode = scoringMode.value;
    detectionWeight.readOnly = false;
    blockingWeight.readOnly = false;
    if (mode === "detect_only") {
      detectionWeight.value = "100";
      blockingWeight.value = "0";
      scoringHelp.textContent =
        "Blocking outcomes remain visible but do not affect the score. Edit either percentage to switch to Custom.";
    } else if (mode === "prevention_first") {
      detectionWeight.value = "40";
      blockingWeight.value = "60";
      scoringHelp.textContent =
        "Detection contributes 40% and blocking contributes 60%. Edit either percentage to switch to Custom.";
    } else if (mode === "auto") {
      detectionWeight.value = "40";
      blockingWeight.value = "60";
      scoringHelp.textContent =
        "The server resolves Automatic from submitted policies. Edit either percentage to switch to Custom.";
    } else {
      scoringHelp.textContent =
        "Choose your own detection and blocking percentages; together they must total 100%.";
    }
    updateScoringTotal();
  }

  function switchToCustomScoring() {
    if (!scoringMode) return;
    if (scoringMode.value !== "custom") {
      scoringMode.value = "custom";
      configureScoringMode();
      return;
    }
    updateScoringTotal();
  }

  scoringMode?.addEventListener("change", configureScoringMode);
  detectionWeight?.addEventListener("input", switchToCustomScoring);
  blockingWeight?.addEventListener("input", switchToCustomScoring);
  configureScoringMode();

  const autoOption = scoringMode?.querySelector('option[value="auto"]');
  function applyMixedModeGuard() {
    if (!scoringMode || !autoOption) return;
    const mixed = Boolean(document.querySelector("[data-mixed-modes]"));
    autoOption.disabled = mixed;
    scoringMode.setCustomValidity(
      mixed && scoringMode.value === "auto"
        ? "The selected packages mix detect-only and blocking policies. Choose Detection only, Prevention first, or Custom."
        : ""
    );
  }
  document.body.addEventListener("htmx:afterSwap", applyMixedModeGuard);
  scoringMode?.addEventListener("change", applyMixedModeGuard);
  applyMixedModeGuard();

  const packageUpload = document.querySelector("[data-package-upload]");
  const uploadSummary = document.querySelector("[data-upload-summary]");
  const uploadList = document.querySelector("[data-upload-list]");
  const uploadCount = document.querySelector("[data-upload-count]");
  const uploadEmpty = document.querySelector("[data-upload-empty]");
  const uploadError = document.querySelector("[data-upload-error]");
  const clearUploads = document.querySelector("[data-clear-uploads]");

  if (packageUpload && uploadSummary && uploadList) {
    let selectedUploads = [];
    const maximumFiles = 20;
    const maximumFileBytes = 100 * 1024 * 1024;

    function fileKey(file) {
      return `${file.name}\u0000${file.size}\u0000${file.lastModified}`;
    }

    function formatFileSize(bytes) {
      if (bytes < 1024) return `${bytes} B`;
      if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
      return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    }

    function syncUploadInput() {
      const transfer = new DataTransfer();
      selectedUploads.forEach((file) => transfer.items.add(file));
      packageUpload.files = transfer.files;
    }

    function showUploadError(message) {
      if (!uploadError) return;
      uploadError.textContent = message;
      uploadError.hidden = !message;
    }

    function renderUploads() {
      uploadList.replaceChildren();
      selectedUploads.forEach((file) => {
        const item = document.createElement("li");
        const details = document.createElement("div");
        const name = document.createElement("strong");
        const size = document.createElement("span");
        const remove = document.createElement("button");

        name.textContent = file.name;
        size.textContent = formatFileSize(file.size);
        details.className = "upload-file-details";
        details.append(name, size);

        remove.type = "button";
        remove.className = "remove-upload";
        remove.textContent = "Remove";
        remove.setAttribute("aria-label", `Remove ${file.name}`);
        remove.addEventListener("click", () => {
          const key = fileKey(file);
          selectedUploads = selectedUploads.filter(
            (candidate) => fileKey(candidate) !== key
          );
          syncUploadInput();
          showUploadError("");
          renderUploads();
        });

        item.append(details, remove);
        uploadList.append(item);
      });

      const count = selectedUploads.length;
      uploadSummary.hidden = count === 0;
      if (uploadEmpty) {
        uploadEmpty.hidden = count !== 0;
        uploadEmpty.textContent = count === 0 ? "No new ZIPs selected yet." : "";
      }
      if (uploadCount) {
        uploadCount.textContent = `(${count} ${count === 1 ? "file" : "files"})`;
      }
    }

    packageUpload.addEventListener("change", () => {
      const additions = [...packageUpload.files];
      const existingKeys = new Set(selectedUploads.map(fileKey));
      const rejected = [];

      additions.forEach((file) => {
        if (!file.name.toLowerCase().endsWith(".zip")) {
          rejected.push(`${file.name} is not a ZIP`);
          return;
        }
        if (file.size > maximumFileBytes) {
          rejected.push(`${file.name} is larger than 100 MB`);
          return;
        }
        const key = fileKey(file);
        if (existingKeys.has(key)) return;
        if (selectedUploads.length >= maximumFiles) {
          rejected.push("No more than 20 uploaded ZIPs are allowed");
          return;
        }
        selectedUploads.push(file);
        existingKeys.add(key);
      });

      syncUploadInput();
      showUploadError(rejected.join(". "));
      renderUploads();
    });

    clearUploads?.addEventListener("click", () => {
      selectedUploads = [];
      syncUploadInput();
      showUploadError("");
      renderUploads();
      packageUpload.focus();
    });

    renderUploads();
  }

  const panel = document.querySelector("[data-job-id]");
  if (!panel) return;
  const jobId = panel.dataset.jobId;
  const progress = document.getElementById("job-progress");
  const status = document.getElementById("job-status");
  const stage = document.getElementById("job-stage");
  const message = document.getElementById("job-message");
  const error = document.getElementById("job-error");

  async function poll() {
    try {
      const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`, {
        credentials: "same-origin",
        headers: { Accept: "application/json" }
      });
      if (!response.ok) throw new Error(`Status request failed (${response.status})`);
      const job = await response.json();
      progress.value = job.progress;
      progress.textContent = `${job.progress}%`;
      status.textContent = job.status;
      stage.textContent = job.stage;
      message.textContent = job.message;
      if (job.error) {
        error.textContent = job.error;
        error.classList.remove("hidden");
      }
      if (job.status === "completed" && job.comparison_id) {
        window.location.replace(`/comparisons/${encodeURIComponent(job.comparison_id)}`);
        return;
      }
      if (!["failed", "interrupted"].includes(job.status)) {
        window.setTimeout(poll, 1000);
      }
    } catch (pollError) {
      error.textContent = pollError.message;
      error.classList.remove("hidden");
      window.setTimeout(poll, 3000);
    }
  }
  poll();
});
