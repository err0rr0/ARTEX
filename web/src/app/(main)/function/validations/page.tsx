"use client";

import * as React from "react";

import { toast } from "sonner";

import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { MOCK } from "@/lib/mock/enabled";
import {
  type ValidationAlert,
  type ValidationAlertReview,
  type ValidationApplication,
  type ValidationRun,
  type ValidationReviewResult,
  validationApi,
} from "@/lib/validation-api";

import { SASTReportImport } from "./sast-report-import";

const verdicts: Record<string, string> = {
  confirmed: "漏洞存在",
  false_positive: "误报",
  uncertain: "不确定",
  not_reproduced: "本次未复现",
  blocked: "验证阻塞",
  not_applicable: "不适用",
};

function errorText(error: unknown) {
  return error instanceof Error ? error.message : "请求失败";
}

export default function ValidationsPage() {
  const [applications, setApplications] = React.useState<ValidationApplication[]>([]);
  const [appTotal, setAppTotal] = React.useState(0);
  const [appPage, setAppPage] = React.useState(1);
  const [appLimit, setAppLimit] = React.useState(20);
  const [expandedApp, setExpandedApp] = React.useState<string | null>(null);
  const [items, setItems] = React.useState<ValidationAlert[]>([]);
  const [total, setTotal] = React.useState(0);
  const [page, setPage] = React.useState(1);
  const [limit, setLimit] = React.useState(20);
  const [source, setSource] = React.useState("");
  const [sourceDraft, setSourceDraft] = React.useState("");
  const [selected, setSelected] = React.useState("");
  const [alert, setAlert] = React.useState<ValidationAlert | null>(null);
  const [review, setReview] = React.useState<ValidationAlertReview | null>(null);
  const [detailTab, setDetailTab] = React.useState("review");
  const [runs, setRuns] = React.useState<ValidationRun[]>([]);
  const [busy, setBusy] = React.useState(false);
  const [deleteCandidate, setDeleteCandidate] = React.useState<ValidationAlert | null>(null);
  const [deleting, setDeleting] = React.useState(false);
  const [deleteError, setDeleteError] = React.useState("");
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");
  const sequence = React.useRef(0);
  const detailTrigger = React.useRef<HTMLButtonElement>(null);

  const refresh = React.useCallback(async () => {
    const seq = ++sequence.current;
    try {
      const [groups, list, selectedAlert] = await Promise.all([
        validationApi.applications(appPage, source),
        expandedApp === null ? null : validationApi.list(page, source, expandedApp),
        selected ? validationApi.alert(selected) : null,
      ]);
      if (seq !== sequence.current) return;
      const lastAppPage = Math.max(1, Math.ceil(groups.total / groups.limit));
      if (appPage > lastAppPage) {
        setAppPage(lastAppPage);
      }
      if (list) {
        const lastPage = Math.max(1, Math.ceil(list.total / list.limit));
        if (page > lastPage) setPage(lastPage);
        setLimit(list.limit);
      }
      setApplications(groups.items);
      setAppTotal(groups.total);
      setAppLimit(groups.limit);
      setItems(list?.items ?? []);
      setTotal(list?.total ?? 0);
      setAlert(selectedAlert?.alert ?? null);
      setReview(selectedAlert?.review ?? null);
      setRuns(selectedAlert?.runs ?? []);
      setError("");
    } catch (e) {
      if (seq === sequence.current) setError(errorText(e));
    } finally {
      if (seq === sequence.current) setLoading(false);
    }
  }, [appPage, expandedApp, page, source, selected]);

  React.useEffect(() => {
    void refresh();
    return () => {
      sequence.current++;
    };
  }, [refresh]);
  function resetDetail() {
    sequence.current++;
    setAlert(null);
    setReview(null);
    setDetailTab("review");
    setRuns([]);
    setError("");
  }
  function choose(item: ValidationAlert, trigger: HTMLButtonElement) {
    detailTrigger.current = trigger;
    resetDetail();
    setSelected(item.id);
  }
  function closeDetail() {
    resetDetail();
    setSelected("");
  }
  function changeApplication(appID: string | null) {
    if (appID === expandedApp && page === 1) return;
    setExpandedApp(appID);
    setPage(1);
    setItems([]);
    setTotal(0);
    if (appID !== null) setLoading(true);
  }
  async function act(action: () => Promise<void>) {
    setBusy(true);
    try {
      await action();
      await refresh();
    } catch (e) {
      toast.error(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function deleteAlert() {
    if (!deleteCandidate || deleting) return;
    setDeleting(true);
    setDeleteError("");
    try {
      await validationApi.deleteAlert(deleteCandidate.id);
      setDeleteCandidate(null);
      toast.success("告警已删除");
      if (selected === deleteCandidate.id) {
        closeDetail();
      } else {
        await refresh();
      }
    } catch (e) {
      setDeleteError(errorText(e));
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="space-y-6 p-4 md:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">白盒复核</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            接收白盒告警，查看材料并登记人工复核结论。
          </p>
        </div>
        <Button variant="outline" onClick={() => void refresh()}>
          刷新
        </Button>
      </div>
      {error && !selected ? (
        <p role="alert" className="text-destructive text-sm">
          {error}
        </p>
      ) : null}
      <Card>
        <CardHeader>
          <CardTitle>接收告警</CardTitle>
          <CardDescription>粘贴单条告警或批量报告，也可以上传 JSON 文件。</CardDescription>
        </CardHeader>
        <CardContent>
          <SASTReportImport onImported={() => void refresh()} />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>告警列表</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              setSource(sourceDraft.trim());
              setAppPage(1);
              changeApplication(null);
            }}
          >
            <Input
              aria-label="告警来源"
              placeholder="按来源精确筛选，如 sca-audit / internal-sast"
              value={sourceDraft}
              onChange={(e) => setSourceDraft(e.target.value)}
            />
            <Button type="submit" variant="outline">
              筛选
            </Button>
          </form>
          <Accordion
            type="single"
            collapsible
            value={expandedApp === null ? "" : `app:${expandedApp}`}
            onValueChange={(value) => changeApplication(value ? value.slice(4) : null)}
          >
            {applications.map((app) => (
              <AccordionItem key={app.app_id} value={`app:${app.app_id}`}>
                <AccordionTrigger className="items-center gap-3 px-2">
                  <span className="min-w-0 wrap-anywhere">{app.app_id || "未标识应用"}</span>
                  <Badge variant="secondary" className="shrink-0">
                    {app.count} 条告警
                  </Badge>
                </AccordionTrigger>
                <AccordionContent className="h-auto">
                  {expandedApp === app.app_id ? (
                    <div className="space-y-2">
                      <ScrollArea
                        key={page}
                        type="auto"
                        className="[&_[data-slot=scroll-area-viewport]]:max-h-[min(28rem,55dvh)] [&_[data-slot=scroll-area-viewport]>div]:block!"
                      >
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>告警 / 外部 ID</TableHead>
                              <TableHead>来源 / 批次</TableHead>
                              <TableHead>类型</TableHead>
                              <TableHead>访问入口</TableHead>
                              <TableHead>操作</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {items.map((item) => (
                              <TableRow key={item.id} className={selected === item.id ? "bg-muted/40" : ""}>
                                <TableCell className="max-w-80 wrap-anywhere whitespace-normal">
                                  <p className="font-medium">{item.title}</p>
                                  <p className="text-muted-foreground text-xs">
                                    #{item.id} · {item.external_id}
                                  </p>
                                </TableCell>
                                <TableCell>
                                  {item.source}
                                  <p className="text-muted-foreground text-xs">{item.scan_id || "未提供批次"}</p>
                                </TableCell>
                                <TableCell>
                                  {item.vulnerability_type}
                                  <p className="text-muted-foreground text-xs">{item.severity}</p>
                                </TableCell>
                                <TableCell className="max-w-64 break-all whitespace-normal">
                                  {item.target_url || "待补充"}
                                </TableCell>
                                <TableCell>
                                  <div className="flex gap-2">
                                    <Button
                                      variant="outline"
                                      size="sm"
                                      aria-haspopup="dialog"
                                      onClick={(event) => choose(item, event.currentTarget)}
                                    >
                                      查看 / 复核
                                    </Button>
                                    <Button
                                      variant="destructive"
                                      size="sm"
                                      disabled={busy || deleting || MOCK}
                                      onClick={() => {
                                        setDeleteError("");
                                        setDeleteCandidate(item);
                                      }}
                                    >
                                      删除
                                    </Button>
                                  </div>
                                </TableCell>
                              </TableRow>
                            ))}
                            {!items.length ? (
                              <TableRow>
                                <TableCell colSpan={5} className="text-muted-foreground py-8 text-center">
                                  {loading ? "加载中…" : "该应用暂无告警"}
                                </TableCell>
                              </TableRow>
                            ) : null}
                          </TableBody>
                        </Table>
                      </ScrollArea>
                      <div className="text-muted-foreground flex items-center justify-between text-sm">
                        <span>
                          共 {total} 条 · 第 {page} 页
                        </span>
                        <div className="flex gap-2">
                          <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage(page - 1)}>
                            上一页
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={page * limit >= total}
                            onClick={() => setPage(page + 1)}
                          >
                            下一页
                          </Button>
                        </div>
                      </div>
                    </div>
                  ) : null}
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
          {!applications.length ? (
            <p className="text-muted-foreground py-8 text-center text-sm">{loading ? "加载中…" : "暂无应用告警"}</p>
          ) : null}
          {appTotal > 0 ? (
            <div className="text-muted-foreground flex items-center justify-between text-sm">
              <span>
                共 {appTotal} 个应用分组 · 第 {appPage} 页
              </span>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={appPage <= 1}
                  onClick={() => {
                    changeApplication(null);
                    setAppPage(appPage - 1);
                  }}
                >
                  上一页应用
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={appPage * appLimit >= appTotal}
                  onClick={() => {
                    changeApplication(null);
                    setAppPage(appPage + 1);
                  }}
                >
                  下一页应用
                </Button>
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>
      <AlertDialog
        open={deleteCandidate !== null}
        onOpenChange={(open) => {
          if (!open && !deleting) setDeleteCandidate(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除告警</AlertDialogTitle>
            <AlertDialogDescription className="wrap-anywhere">
              将永久删除告警 #{deleteCandidate?.id}「{deleteCandidate?.title}」及其复核记录。
            </AlertDialogDescription>
          </AlertDialogHeader>
          {deleteError ? (
            <p role="alert" className="text-destructive text-sm">
              {deleteError}
            </p>
          ) : null}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deleting}
              onClick={(event) => {
                event.preventDefault();
                void deleteAlert();
              }}
            >
              {deleting ? "删除中…" : "确认删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <Dialog
        open={selected !== ""}
        onOpenChange={(open) => {
          if (!open && !busy) closeDetail();
        }}
      >
        <DialogContent
          showCloseButton={false}
          className="flex max-h-[90dvh] flex-col gap-0 overflow-hidden p-0 sm:max-w-5xl"
          onCloseAutoFocus={(event) => {
            if (detailTrigger.current?.isConnected) {
              event.preventDefault();
              detailTrigger.current.focus({ preventScroll: true });
            }
          }}
        >
          <DialogHeader className="bg-muted/30 flex-row items-start justify-between gap-3 border-b px-4 py-4 sm:px-6">
            <div className="min-w-0 space-y-2">
              <DialogTitle className="text-lg leading-snug wrap-anywhere">
                {alert ? `#${alert.id} · ${alert.title}` : "告警详情"}
              </DialogTitle>
              <DialogDescription className="wrap-anywhere">
                {alert
                  ? `${alert.source} · ${alert.scan_id || "未提供批次"} · ${alert.external_id}`
                  : `告警 #${selected}`}
              </DialogDescription>
            </div>
            <DialogClose asChild>
              <Button variant="outline" size="sm" className="shrink-0" disabled={busy}>
                关闭
              </Button>
            </DialogClose>
          </DialogHeader>
          {error ? (
            <div role="alert" className="flex shrink-0 items-center gap-3 px-4 py-3 sm:px-6">
              <p className="text-destructive">{error}</p>
              <Button variant="outline" size="sm" onClick={() => void refresh()}>
                重试
              </Button>
            </div>
          ) : null}
          {!alert && !error ? (
            <p role="status" className="text-muted-foreground px-4 py-5 sm:px-6">
              正在读取告警详情…
            </p>
          ) : null}
          {alert ? (
            <Tabs value={detailTab} onValueChange={setDetailTab} className="min-h-0 overflow-hidden">
              <div className="shrink-0 px-4 pt-3 sm:px-6">
                <TabsList aria-label="告警详情分类">
                  <TabsTrigger value="review">告警材料</TabsTrigger>
                  <TabsTrigger value="validation">人工复核</TabsTrigger>
                </TabsList>
              </div>
              <TabsContent value="review" className="min-h-0 space-y-5 overflow-y-auto px-4 pb-5 sm:px-6">
                <p className="text-sm wrap-anywhere">
                  仓库：{alert.repository || "未提供"} · 模块：{alert.module || "未提供"} · 扫描版本：
                  {alert.commit || "未知"}
                </p>
                <details open>
                  <summary className="cursor-pointer text-sm">查看告警描述和源码上下文</summary>
                  <p className="mt-3 text-sm whitespace-pre-wrap">{alert.description}</p>
                  <pre className="bg-muted mt-2 max-h-80 overflow-auto rounded p-3 text-xs">
                    {JSON.stringify(alert.context, null, 2)}
                  </pre>
                </details>
                {review ? (
                  <details open>
                    <summary className="cursor-pointer text-sm">白盒代码与复核材料</summary>
                    {review.problem_code ? (
                      <>
                        <p className="text-muted-foreground mt-2 text-xs">
                          问题代码{review.problem_code_truncated ? " · 仅显示前 16 KiB" : ""}
                        </p>
                        <pre className="bg-muted mt-2 max-h-80 overflow-auto rounded p-3 text-xs">
                          <code>{review.problem_code}</code>
                        </pre>
                      </>
                    ) : null}
                    {review.poc_provided ? (
                      <div className="text-muted-foreground mt-2 space-y-1 text-sm">
                        {review.poc_text ? (
                          <>
                            <p className="text-xs">白盒 PoC{review.poc_truncated ? " · 仅保留前 16 KiB" : ""}</p>
                            <pre className="bg-muted text-foreground max-h-80 overflow-auto rounded p-3 text-xs">
                              <code>{review.poc_text}</code>
                            </pre>
                          </>
                        ) : (
                          <p>重导原报告可补齐 PoC 正文。</p>
                        )}
                        <p>
                          PoC 原报告定位：{alert.source} / {alert.scan_id || "未提供批次"} / {alert.external_id}
                        </p>
                        {review.poc_sha256 ? (
                          <p className="wrap-anywhere">
                            PoC 内容指纹（SHA-256）：<code>{review.poc_sha256}</code>
                          </p>
                        ) : null}
                      </div>
                    ) : null}
                  </details>
                ) : null}
              </TabsContent>
              <TabsContent value="validation" className="min-h-0 space-y-5 overflow-y-auto px-4 pb-5 sm:px-6">
                <form
                  className="space-y-3"
                  onSubmit={(event) => {
                    event.preventDefault();
                    const form = event.currentTarget;
                    const fields = new FormData(form);
                    const result = String(fields.get("result") ?? "") as ValidationReviewResult;
                    const note = String(fields.get("note") ?? "");
                    void act(async () => {
                      await validationApi.saveReview(alert.id, result, note);
                      form.reset();
                      toast.success("复核结论已保存");
                    });
                  }}
                >
                  <div className="space-y-1.5">
                    <Label htmlFor="validation-review-result">复核结论</Label>
                    <select
                      id="validation-review-result"
                      name="result"
                      className="bg-background w-full rounded-md border p-2 text-sm"
                      required
                      defaultValue=""
                      disabled={busy || MOCK}
                    >
                      <option value="" disabled>请选择</option>
                      <option value="vulnerability_exists">漏洞存在</option>
                      <option value="false_positive">误报</option>
                      <option value="uncertain">不确定</option>
                    </select>
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="validation-review-note">复核说明</Label>
                    <Textarea id="validation-review-note" name="note" required maxLength={2000} disabled={busy || MOCK} />
                  </div>
                  <Button type="submit" disabled={busy || MOCK}>{busy ? "保存中…" : "保存复核结论"}</Button>
                </form>
                <div className="space-y-3">
                  <h3 className="font-medium">复核记录</h3>
                  {runs.length ? (
                    <ul className="space-y-2">
                      {runs.map((run) => (
                        <li key={run.id} className="space-y-1 rounded-md border p-3">
                          <p className="text-sm font-medium">{verdicts[run.verdict] ?? "未得出结论"}</p>
                          <p className="text-muted-foreground text-xs">
                            #{run.id} · {new Date(run.finished_at ?? run.created_at).toLocaleString("zh-CN")}
                          </p>
                          {run.summary ? <p className="text-sm wrap-anywhere whitespace-pre-wrap">{run.summary}</p> : null}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-muted-foreground text-sm">暂无复核记录。</p>
                  )}
                </div>
              </TabsContent>
            </Tabs>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
