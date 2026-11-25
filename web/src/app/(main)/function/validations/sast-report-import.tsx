"use client";

import * as React from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { MOCK } from "@/lib/mock/enabled";
import { type SASTReportResult, validationApi } from "@/lib/validation-api";

const statuses = {
  ready_to_import: "可导入",
  created: "已新增",
  existing: "已存在",
  conflict: "内容冲突",
  failed: "保存失败",
};

export function SASTReportImport({ onImported }: { onImported: () => void }) {
  const [mode, setMode] = React.useState<"file" | "paste">("paste");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [result, setResult] = React.useState<SASTReportResult | null>(null);

  function clearResult() {
    setError("");
    setResult(null);
  }

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const form = new FormData(event.currentTarget);
    setBusy(true);
    clearResult();
    try {
      const input = form.get("report");
      let text: string;
      if (mode === "paste") {
        if (typeof input !== "string" || !input.trim()) throw new Error("请粘贴报告 JSON");
        if (new Blob([input]).size > 5 * 1024 * 1024) throw new Error("批量导入请求最多 5 MiB");
        text = input;
      } else {
        if (!(input instanceof File) || !input.size) throw new Error("请选择一份报告文件");
        if (input.size > 5 * 1024 * 1024) throw new Error("批量导入请求最多 5 MiB");
        text = await input.text();
      }
      let report: unknown;
      try {
        report = JSON.parse(text.replace(/^\uFEFF/, ""));
      } catch {
        throw new Error("请输入原始 JSON，或上传白盒导出的 JSON 文件");
      }
      const imported = await validationApi.importSASTReport(report);
      setResult(imported);
      onImported();
    } catch (e) {
      setError(e instanceof Error ? e.message : "报告导入失败");
    } finally {
      setBusy(false);
    }
  }

  const scanTotal = result?.report_counts.scanTotal;
  const reportedTotal = result?.report_counts.total;
  const priorities = ([0, 1, 2, 3, 4] as const).flatMap((level) => {
    const count = result?.report_counts[`p${level}Count`];
    return count === undefined ? [] : [`P${level} ${count} 条`];
  });
  return (
    <div className="space-y-3">
      <form onSubmit={(e) => void submit(e)} onChange={clearResult}>
        <fieldset disabled={busy || MOCK} className="space-y-3">
          <fieldset className="flex flex-wrap gap-2" aria-label="报告输入方式">
            <Button
              type="button"
              variant={mode === "file" ? "secondary" : "outline"}
              aria-pressed={mode === "file"}
              onClick={() => {
                if (mode === "file") return;
                setMode("file");
                clearResult();
              }}
            >
              上传报告
            </Button>
            <Button
              type="button"
              variant={mode === "paste" ? "secondary" : "outline"}
              aria-pressed={mode === "paste"}
              onClick={() => {
                if (mode === "paste") return;
                setMode("paste");
                clearResult();
              }}
            >
              粘贴告警 JSON
            </Button>
          </fieldset>
          <div className="space-y-1.5">
            {mode === "paste" ? (
              <>
                <Label htmlFor="sast-report-json">告警 JSON</Label>
                <Textarea
                  id="sast-report-json"
                  name="report"
                  rows={8}
                  className="font-mono text-xs"
                  required
                  placeholder={
                    '{"repoURL":"https://git.example.com/team/app.git","findings":[{"id":"VULN-01","cwe":"CWE-532","title":"日志内容待复核"}]}'
                  }
                />
              </>
            ) : (
              <>
                <Label htmlFor="sast-report-file">白盒报告文件</Label>
                <Input id="sast-report-file" name="report" type="file" accept=".json,.txt,application/json" required />
              </>
            )}
          </div>
          <Button type="submit">{result?.totals.failed ? "重试导入" : "导入告警"}</Button>
        </fieldset>
      </form>
      {busy ? <p role="status">正在处理报告…</p> : null}
      {error ? (
        <p role="alert" className="text-destructive text-sm">
          {error}
        </p>
      ) : null}
      {result ? (
        <div className="space-y-2">
          <p role="status" className="text-sm">
            导入结果
            {` · 来源 ${result.source}`}
            {result.app_id ? ` · 应用 ${result.app_id}` : null}
            {result.scan_id && !result.local_batch ? ` · 批次 ${result.scan_id}` : null} · 收到 {result.finding_count}{" "}
            条明细
            {scanTotal === undefined ? null : ` · 扫描总数 ${scanTotal}`}
            {reportedTotal === undefined ? null : ` · 报告明细总数 ${reportedTotal}`}
          </p>
          {result.local_batch ? (
            <p className="text-muted-foreground text-sm">已使用 ARTEX 本地批次。回传结果需要白盒报告提供 jobId。</p>
          ) : null}
          {priorities.length ? (
            <p className="text-muted-foreground text-sm">白盒分级统计 · {priorities.join(" · ")}</p>
          ) : null}
          <p className="text-sm">
            新增 {result.totals.created ?? 0} · 已存在 {result.totals.existing ?? 0} · 冲突{" "}
            {result.totals.conflict ?? 0} · 失败 {result.totals.failed ?? 0}
          </p>
          {result.results.length ? (
            <div className="max-h-80 overflow-auto rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>白盒告警</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead>ARTEX 告警 ID</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {result.results.map((row) => (
                    <TableRow key={row.external_id}>
                      <TableCell className="wrap-anywhere whitespace-normal">
                        {row.title}
                        <div className="text-muted-foreground text-xs">{row.external_id}</div>
                      </TableCell>
                      <TableCell className="whitespace-normal">
                        {statuses[row.status]}
                        {row.error ? <div className="text-muted-foreground text-xs">{row.error}</div> : null}
                      </TableCell>
                      <TableCell>{row.alert_id ?? "—"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
