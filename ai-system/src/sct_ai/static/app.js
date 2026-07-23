"use strict";

document.addEventListener("DOMContentLoaded", () => {
  if (window.htmx) {
    window.htmx.config.historyCacheSize = 0;
    window.htmx.config.allowEval = false;
    window.htmx.config.allowScriptTags = false;
    window.htmx.config.selfRequestsOnly = true;
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
