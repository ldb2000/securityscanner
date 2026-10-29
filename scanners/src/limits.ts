// Operational limits for ACTIVE (DAST) adapters: rate limiting and a hard
// time-box. Defensive defaults keep active scans gentle and bounded; override
// via env for authorized, scoped engagements.

export interface ActiveLimits {
  /** Max requests per second the adapter should send. */
  rateLimit: number;
  /** Hard wall-clock time-box for the adapter run, in ms. */
  timeoutMs: number;
}

function intEnv(name: string, def: number): number {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? Math.floor(v) : def;
}

export function activeLimits(): ActiveLimits {
  return {
    rateLimit: intEnv("SEC_SCAN_DAST_RATE_LIMIT", 50),
    timeoutMs: intEnv("SEC_SCAN_DAST_TIMEOUT_MS", 300_000),
  };
}
