import { http } from "@/lib/api";
import { MOCK } from "@/lib/mock/enabled";

export interface ValidationInput {
  source: string;
  scan_id: string;
  external_id: string;
  title: string;
  vulnerability_type: string;
  severity?: string;
  repository?: string;
  commit?: string;
  module?: string;
  description?: string;
  context?: Record<string, unknown>;
  target_url?: string;
}
export interface SASTReportResult {
  source: string;
  scan_id: string;
  local_batch?: boolean;
  app_id?: string;
  submitted: boolean;
  report_counts: Partial<Record<"scanTotal" | "total" | `p${0 | 1 | 2 | 3 | 4}Count`, number>>;
  finding_count: number;
  results: {
    external_id: string;
    title: string;
    status: "ready_to_import" | "created" | "existing" | "conflict" | "failed";
    alert_id?: string;
    error?: string;
  }[];
  totals: Partial<Record<SASTReportResult["results"][number]["status"], number>>;
}
export interface ValidationAlert extends ValidationInput {
  id: string;
  readiness: "ready" | "needs_input";
  blocking_reasons: string[];
  created_at: string;
  updated_at: string;
}
export interface ValidationAlertReview {
  problem_code?: string;
  problem_code_truncated?: boolean;
  poc_provided: boolean;
  poc_sha256?: string;
  poc_text?: string;
  poc_truncated?: boolean;
  // POC 原文一比一留档（不脱敏、不截断）
}
export interface ValidationApplication {
  app_id: string;
  count: number;
}
export type ValidationReviewResult = "vulnerability_exists" | "false_positive" | "uncertain";

export interface ValidationRun {
  id: string;
  alert_id: string;
  status: string;
  verdict: string;
  summary: string;
  created_at: string;
  finished_at?: string;
}

function realMode() {
  if (MOCK) throw new Error("演示模式只读。");
}

export const validationApi = {
  async list(page: number, source: string, appID: string) {
    if (MOCK) return { items: [] as ValidationAlert[], total: 0, page, limit: 20 };
    return http<{ items: ValidationAlert[]; total: number; page: number; limit: number }>(
      `/validation/alerts?${new URLSearchParams({ page: String(page), source, app_id: appID })}`,
    );
  },
  async applications(page: number, source: string) {
    if (MOCK) return { items: [] as ValidationApplication[], total: 0, page, limit: 20 };
    return http<{ items: ValidationApplication[]; total: number; page: number; limit: number }>(
      `/validation/applications?${new URLSearchParams({ page: String(page), source })}`,
    );
  },
  alert(id: string) {
    realMode();
    return http<{ alert: ValidationAlert; runs: ValidationRun[]; review?: ValidationAlertReview | null }>(
      `/validation/alerts/${id}`,
    );
  },
  deleteAlert(id: string) {
    realMode();
    return http<void>(`/validation/alerts/${id}`, { method: "DELETE" });
  },
  importSASTReport(report: unknown) {
    realMode();
    return http<SASTReportResult>("/validation/imports/sast-report", {
      method: "POST",
      body: JSON.stringify({ submit: true, report }),
    });
  },
  saveReview(id: string, result: ValidationReviewResult, note: string) {
    realMode();
    return http<{ run: ValidationRun }>(`/validation/alerts/${id}/reviews`, {
      method: "POST",
      body: JSON.stringify({ result, note }),
    });
  },
};
