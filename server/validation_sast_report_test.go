package server

import (
	"encoding/json"
	"strings"
	"testing"
)

const sampleValidationSASTReport = `{
  "code":0,"message":"ok","data":{
    "jobId":"job-1","scanTotal":9,"p4Count":3,"total":6,
    "findings":[
      {"id":"VULN-01","title":"配置输出需复核","category":"SENSITIVE_DATA",
       "severity":"P1","status":"suspected","confidence":80,"exposureStatus":"unknown",
       "rootCause":"配置对象可能被写入日志","locations":["app/config.go:2"],
       "codeFlow":[{"file":"app/config.go","line":2,"role":"sink","snippet":"omit"}],
       "mergedFromIds":["VULN-09"],"mergedLocations":[["app/config.go:2"]],
       "poc":"omit","exploitability":"omit","gitBlame":{"commitHash":"omit"}},
      {"id":"VULN-02","title":"日志检查","category":"SENSITIVE_DATA"}
    ]
  }
}`

const sampleFlatSASTReport = `{
  "score":70, "p0Count":0, "p1Count":2, "p2Count":1, "p3Count":0,
  "repoURL":"https://git.example.com/team/AppRentMarketH5Web.git",
  "findings":[
    {"id":"VULN-01","cwe":"CWE-321","category":"HARDCODED_SECRET",
     "severity":"P1","title":"配置中有 test-secret-value","secretValue":"test-secret-value",
     "rootCause":"源文件包含 test-secret-value", "locations":["app/config.go:2"],
     "poc":"人工复核备注：检查 test-secret-value","problemCode":"const placeholder = 'test-secret-value';","fixDiff":"exclude-this-field"},
    {"id":"VULN-02","cwe":"CWE-798","severity":"P4","title":"配置需复核",
     "rootCause":"另有 test-secret-value 需要清理"},
    {"id":"VULN-05","cwe":"CWE-532","severity":"P2","title":"日志内容待复核"},
    {"id":"VULN-15","cwe":"CWE-532","severity":"P1","title":"另一处日志内容待复核"}
  ]
}`

func TestValidationSASTFlatReportConversion(t *testing.T) {
	input := validationSASTImport{Report: json.RawMessage(sampleFlatSASTReport)}
	localAlerts, local, err := convertValidationSASTReport(input)
	if err != nil || local.Source != "internal-sast" || !local.LocalBatch ||
		!strings.HasPrefix(local.ScanID, localValidationBatchPrefix) || len(localAlerts) != 4 ||
		localAlerts[0].ScanID != local.ScanID {
		t.Fatalf("expected a default source and local batch: %+v (%v)", local, err)
	}
	cloned := input
	cloned.Report = json.RawMessage(strings.Replace(sampleFlatSASTReport, `"score":70`, `"score":71`, 1))
	if _, result, err := convertValidationSASTReport(cloned); err != nil || result.ScanID != local.ScanID {
		t.Fatalf("local batch changed after a statistics-only edit: %+v (%v)", result, err)
	}
	cloned.Report = json.RawMessage(strings.Replace(sampleFlatSASTReport, `"score":70`, `"score":70,"jobId":"upstream-job-1","appId":"project-uuid"`, 1))
	upstreamAlerts, upstream, err := convertValidationSASTReport(cloned)
	if err != nil || upstream.LocalBatch || upstream.ScanID != "upstream-job-1" {
		t.Fatalf("upstream job ID was not used: %+v (%v)", upstream, err)
	}
	if upstream.AppID != "AppRentMarketH5Web" ||
		!strings.Contains(string(upstreamAlerts[0].Context), `"source_app_id":"project-uuid"`) {
		t.Fatal("the original app ID was not persisted independently of the repository grouping label")
	}
	input.ScanID = "batch-flat"
	input.AppID = "legacy-name"
	alerts, result, err := convertValidationSASTReport(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 4 || result.FindingCount != 4 || result.ReportCounts["p1Count"] != 2 ||
		alerts[0].ScanID != input.ScanID || alerts[0].Repository != "https://git.example.com/team/AppRentMarketH5Web.git" ||
		result.AppID != "AppRentMarketH5Web" || !strings.Contains(string(alerts[0].Context), `"app_id":"AppRentMarketH5Web"`) ||
		alerts[0].VulnerabilityType != "CWE-321" || alerts[1].Severity != "unknown" ||
		!strings.Contains(string(alerts[1].Context), `"original_severity":"P4"`) || alerts[0].TargetURL != "" {
		t.Fatalf("unexpected conversion: %+v %+v", alerts, result)
	}
	encoded, err := json.Marshal([]any{alerts, result})
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"test-secret-value", "exclude-this-field", "secretValue"} {
		if strings.Contains(string(encoded), unwanted) {
			t.Fatalf("converted batch includes %q", unwanted)
		}
	}
	if !strings.Contains(alerts[0].Title, "[已脱敏]") || !strings.Contains(alerts[1].Description, "[已脱敏]") {
		t.Fatal("expected redaction in title and across findings")
	}
	review := alerts[0].Review
	if review == nil || !review.POCProvided || review.ProblemCode != "const placeholder = '[已脱敏]';" ||
		review.POCText != "人工复核备注：检查 [已脱敏]" ||
		strings.Contains(string(alerts[0].Context), "const placeholder") ||
		strings.Contains(string(alerts[0].Context), "人工复核备注") || alerts[1].Review != nil {
		t.Fatalf("unexpected static review: %+v", review)
	}
}

func TestValidationSASTReportConversion(t *testing.T) {
	input := validationSASTImport{
		Source: " internal-sast ", AppID: "app-1", Repository: "repo-1",
		Commit: "scan-commit", Module: "module-1", Report: json.RawMessage(sampleValidationSASTReport),
	}
	alerts, result, err := convertValidationSASTReport(input)
	if err != nil {
		t.Fatal(err)
	}
	if result.ReportCounts["scanTotal"] != 9 || result.ReportCounts["p4Count"] != 3 ||
		result.FindingCount != 2 || len(alerts) != 2 {
		t.Fatalf("unexpected batch: %+v", result)
	}
	a := alerts[0]
	if a.Source != "internal-sast" || a.ScanID != "job-1" || a.ExternalID != "VULN-01" ||
		a.Severity != "unknown" || a.Commit != "scan-commit" || a.Module != "module-1" ||
		a.VulnerabilityType != "SENSITIVE_DATA" || a.Description != "配置对象可能被写入日志" || a.TargetURL != "" {
		t.Fatalf("unexpected conversion: %+v", a)
	}
	context := string(a.Context)
	for _, want := range []string{`"app_id":"app-1"`, `"original_severity":"P1"`, `"status":"suspected"`, `"merged_from_ids":["VULN-09"]`} {
		if !strings.Contains(context, want) {
			t.Errorf("context missing %s: %s", want, context)
		}
	}
	if strings.Contains(context, "omit") {
		t.Fatalf("context included a field outside the allowlist: %s", context)
	}
	input.Report = json.RawMessage(strings.Replace(sampleValidationSASTReport, "VULN-02", " VULN-01 ", 1))
	if _, _, err := convertValidationSASTReport(input); err == nil || !strings.Contains(err.Error(), "重复") {
		t.Fatalf("expected duplicate ID error, got %v", err)
	}
}
