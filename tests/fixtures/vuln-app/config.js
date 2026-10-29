// Placeholder config for the secrets-scanning FIXTURE. Values are intentionally
// non-secret so the project's own self-scan stays clean; the e2e test uses a
// mock gitleaks that reports a finding regardless of this file's content.
module.exports = { apiKey: "REPLACE_WITH_YOUR_KEY", token: "ghp_REPLACE_ME" };
