package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

const (
	maxValidationReportBytes    = 5 << 20
	maxValidationReportRows     = 500
	maxValidationReviewBytes    = 16 << 10
	defaultValidationSASTSource = "internal-sast"
	localValidationBatchPrefix  = "local-report:"
)

type validationSASTImport struct {
	Source     string          `json:"source"`
	ScanID     string          `json:"scan_id"`
	AppID      string          `json:"app_id"`
	Repository string          `json:"repository"`
	Commit     string          `json:"commit"`
	Module     string          `json:"module"`
	Submit     bool            `json:"submit"`
	Report     json.RawMessage `json:"report"`
}

// Only the report fields used to store static review context are decoded.
type validationSASTReport struct {
	validationSASTData
	Code       json.RawMessage     `json:"code"`
	Data       *validationSASTData `json:"data"`
	ExternalID json.RawMessage     `json:"external_id"`
}

type validationSASTData struct {
	JobID     string                  `json:"jobId"`
	AppID     string                  `json:"appId"`
	RepoURL   string                  `json:"repoURL"`
	ScanTotal *int                    `json:"scanTotal"`
	Total     *int                    `json:"total"`
	P0Count   *int                    `json:"p0Count"`
	P1Count   *int                    `json:"p1Count"`
	P2Count   *int                    `json:"p2Count"`
	P3Count   *int                    `json:"p3Count"`
	P4Count   *int                    `json:"p4Count"`
	Findings  []validationSASTFinding `json:"findings"`
}

type validationSASTFinding struct {
	ID              string                   `json:"id"`
	Title           string                   `json:"title"`
	CWE             string                   `json:"cwe"`
	Category        string                   `json:"category"`
	RootCause       string                   `json:"rootCause"`
	Severity        string                   `json:"severity"`
	Status          string                   `json:"status"`
	ExposureStatus  string                   `json:"exposureStatus"`
	Confidence      *float64                 `json:"confidence"`
	Locations       []string                 `json:"locations"`
	CodeFlow        []validationSASTFlowNode `json:"codeFlow"`
	MergedFromIDs   []string                 `json:"mergedFromIds"`
	MergedLocations [][]string               `json:"mergedLocations"`
	SecretValue     string                   `json:"secretValue"`
	ProblemCode     string                   `json:"problemCode"`
	POC             json.RawMessage          `json:"poc"`
}

type validationSASTAlert struct {
	db.ValidationAlertInput
	Review *db.ValidationAlertReview
}

type validationSASTFlowNode struct {
	File string `json:"file,omitempty"`
	Line *int   `json:"line,omitempty"`
	Role string `json:"role,omitempty"`
}

type validationReportRow struct {
	ExternalID string `json:"external_id"`
	Title      string `json:"title"`
	Status     string `json:"status"`
	AlertID    string `json:"alert_id,omitempty"`
	Error      string `json:"error,omitempty"`
}

type validationReportResult struct {
	Source       string                `json:"source"`
	ScanID       string                `json:"scan_id"`
	LocalBatch   bool                  `json:"local_batch,omitempty"`
	AppID        string                `json:"app_id,omitempty"`
	Submitted    bool                  `json:"submitted"`
	ReportCounts map[string]int        `json:"report_counts"`
	FindingCount int                   `json:"finding_count"`
	Results      []validationReportRow `json:"results"`
	Totals       map[string]int        `json:"totals"`
}

func convertValidationSASTReport(in validationSASTImport) ([]validationSASTAlert, validationReportResult, error) {
	var result validationReportResult
	var report validationSASTReport
	if err := json.Unmarshal(in.Report, &report); err != nil {
		var field *json.UnmarshalTypeError
		if errors.As(err, &field) && field.Field != "" {
			return nil, result, fmt.Errorf("报告字段 %s 类型不正确", field.Field)
		}
		return nil, result, errors.New("报告格式不正确，请提供包含 findings 的 JSON 对象")
	}
	data := report.validationSASTData
	if report.Data == nil && len(report.Code) == 0 && data.Findings == nil && len(report.ExternalID) > 0 {
		return convertSingleValidationAlert(in.Report)
	}
	if report.Data != nil || len(report.Code) > 0 {
		if string(report.Code) != "0" || report.Data == nil || data.Findings != nil {
			return nil, result, errors.New("带响应包装的报告须包含 code: 0 和 data.findings，且只能提供一个 findings 数组")
		}
		data = *report.Data
		if strings.TrimSpace(data.JobID) == "" {
			data.JobID = report.JobID
		}
		if strings.TrimSpace(data.RepoURL) == "" {
			data.RepoURL = report.RepoURL
		}
		topAppID := strings.TrimSpace(report.AppID)
		if strings.TrimSpace(data.AppID) == "" {
			data.AppID = topAppID
		} else if topAppID != "" && strings.TrimSpace(data.AppID) != topAppID {
			return nil, result, errors.New("报告顶层与 data 中的 appId 不一致")
		}
	}
	if data.Findings == nil {
		return nil, result, errors.New("报告缺少 findings 或 data.findings 数组")
	}
	if len(data.Findings) > maxValidationReportRows {
		return nil, result, fmt.Errorf("单次最多处理 %d 条告警", maxValidationReportRows)
	}
	scanID := strings.TrimSpace(data.JobID)
	suppliedScanID := strings.TrimSpace(in.ScanID)
	if scanID == "" {
		scanID = suppliedScanID
	}
	if suppliedScanID != "" && suppliedScanID != scanID {
		return nil, result, errors.New("填写的扫描批次 ID 与报告 jobId 不一致")
	}
	if strings.HasPrefix(scanID, localValidationBatchPrefix) {
		return nil, result, errors.New("local-report: 为 ARTEX 本地批次保留的前缀")
	}
	flatReport := report.Data == nil
	redact := validationReportRedactor(data.Findings)
	base := db.ValidationAlertInput{
		Source: strings.TrimSpace(in.Source), ScanID: scanID,
		Repository: strings.TrimSpace(in.Repository), Commit: strings.TrimSpace(in.Commit), Module: strings.TrimSpace(in.Module),
		Severity: "unknown",
	}
	if base.Repository == "" {
		base.Repository = strings.TrimSpace(data.RepoURL)
	}
	if base.Source == "" {
		base.Source = defaultValidationSASTSource
	}
	appID := validationApplicationFromRepoURL(data.RepoURL)
	sourceAppID := strings.TrimSpace(data.AppID)
	if appID == "" {
		appID = strings.TrimSpace(in.AppID)
	}
	if appID == "" {
		appID = sourceAppID
	}
	for _, field := range []struct {
		name  string
		value string
		limit int
	}{
		{"source", base.Source, 80}, {"scan_id", base.ScanID, 160},
		{"app_id", appID, 500}, {"appId", sourceAppID, 500}, {"repository", base.Repository, 2000},
		{"commit", base.Commit, 256}, {"module", base.Module, 500},
	} {
		if len(field.value) > field.limit || strings.ContainsRune(field.value, 0) {
			return nil, result, fmt.Errorf("%s 含空字符或超过 %d 字节", field.name, field.limit)
		}
		if redact(field.value) != field.value {
			return nil, result, fmt.Errorf("%s 包含报告标记的敏感值，请先脱敏", field.name)
		}
	}
	result = validationReportResult{
		Source: base.Source, ScanID: base.ScanID, AppID: appID, ReportCounts: map[string]int{},
		FindingCount: len(data.Findings),
		Results:      make([]validationReportRow, 0, len(data.Findings)),
		Totals:       map[string]int{},
	}
	for _, count := range []struct {
		key   string
		value *int
	}{
		{"scanTotal", data.ScanTotal}, {"total", data.Total},
		{"p0Count", data.P0Count}, {"p1Count", data.P1Count}, {"p2Count", data.P2Count},
		{"p3Count", data.P3Count}, {"p4Count", data.P4Count},
	} {
		if count.value == nil {
			continue
		}
		if *count.value < 0 {
			return nil, result, fmt.Errorf("%s 必须是非负整数", count.key)
		}
		result.ReportCounts[count.key] = *count.value
	}
	alerts := make([]validationSASTAlert, 0, len(data.Findings))
	seen := make(map[string]bool, len(data.Findings))
	for i, finding := range data.Findings {
		alert := base
		if redact(finding.ID) != finding.ID {
			return nil, result, fmt.Errorf("findings 第 %d 条：告警 ID 包含报告标记的敏感值", i+1)
		}
		alert.ExternalID, alert.Title = finding.ID, redact(finding.Title)
		alert.VulnerabilityType = redact(finding.Category)
		if flatReport && strings.TrimSpace(finding.CWE) != "" {
			alert.VulnerabilityType = redact(strings.TrimSpace(finding.CWE))
		}
		alert.Description = strings.TrimSpace(redact(finding.RootCause))
		alert.Context = finding.context(appID, sourceAppID, redact, flatReport)
		if err := alert.Normalize(); err != nil {
			return nil, result, fmt.Errorf("findings 第 %d 条：%w", i+1, err)
		}
		// PostgreSQL text and JSONB reject NUL, even when escaped in JSON.
		for _, value := range []string{alert.ExternalID, alert.Title, alert.VulnerabilityType, alert.Description} {
			if strings.ContainsRune(value, 0) {
				return nil, result, fmt.Errorf("findings 第 %d 条：告警字段含空字符", i+1)
			}
		}
		if strings.Contains(string(alert.Context), `\u0000`) {
			// Unquoting individual JSON strings distinguishes NUL from literal escape text.
			tokens := json.NewDecoder(strings.NewReader(string(alert.Context)))
			for {
				token, err := tokens.Token()
				if err != nil {
					break
				}
				if decoded, ok := token.(string); ok && strings.ContainsRune(decoded, 0) {
					return nil, result, fmt.Errorf("findings 第 %d 条：上下文含空字符", i+1)
				}
			}
		}
		if seen[alert.ExternalID] {
			return nil, result, fmt.Errorf("findings 第 %d 条：告警 ID 重复", i+1)
		}
		seen[alert.ExternalID] = true
		alerts = append(alerts, validationSASTAlert{ValidationAlertInput: alert, Review: finding.staticReview(redact)})
		result.Results = append(result.Results, validationReportRow{
			ExternalID: alert.ExternalID, Title: alert.Title, Status: "ready_to_import",
		})
	}
	if scanID == "" {
		result.LocalBatch = true
		result.ScanID = localValidationBatchID(alerts)
		for i := range alerts {
			alerts[i].ScanID = result.ScanID
		}
	}
	return alerts, result, nil
}

// Only normalized alert data determines the local batch. Presentation order,
// report statistics and separately archived review material do not affect it.
func localValidationBatchID(alerts []validationSASTAlert) string {
	inputs := make([]db.ValidationAlertInput, 0, len(alerts))
	for _, alert := range alerts {
		inputs = append(inputs, alert.ValidationAlertInput)
	}
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].ExternalID < inputs[j].ExternalID })
	raw, _ := json.Marshal(inputs)
	hash := sha256.Sum256(raw)
	return localValidationBatchPrefix + hex.EncodeToString(hash[:])
}

func validationApplicationFromRepoURL(raw string) string {
	repo, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || repo.Scheme == "" || repo.Hostname() == "" {
		return ""
	}
	name, err := url.PathUnescape(path.Base(strings.TrimRight(repo.EscapedPath(), "/")))
	if err != nil || strings.ContainsAny(name, "/\\") {
		return ""
	}
	name = strings.TrimSpace(strings.TrimSuffix(name, ".git"))
	if name == "." || name == ".." {
		return ""
	}
	return name
}

func convertSingleValidationAlert(raw json.RawMessage) ([]validationSASTAlert, validationReportResult, error) {
	if len(raw) > maxValidationAlertBytes {
		return nil, validationReportResult{}, errors.New("单条通用告警 JSON 最多 192 KiB")
	}
	var alert db.ValidationAlertInput
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&alert); err != nil {
		return nil, validationReportResult{}, fmt.Errorf("单条通用告警格式不正确：%w", err)
	}
	if err := alert.Normalize(); err != nil {
		return nil, validationReportResult{}, err
	}
	result := validationReportResult{
		Source: alert.Source, ScanID: alert.ScanID, FindingCount: 1,
		ReportCounts: map[string]int{}, Totals: map[string]int{},
		Results: []validationReportRow{{ExternalID: alert.ExternalID, Title: alert.Title, Status: "ready_to_import"}},
	}
	return []validationSASTAlert{{ValidationAlertInput: alert}}, result, nil
}

func (f validationSASTFinding) staticReview(redact func(string) string) *db.ValidationAlertReview {
	var poc string
	hasPOC := json.Unmarshal(f.POC, &poc) == nil && strings.TrimSpace(poc) != ""

	code, truncated := validationReviewText(f.ProblemCode, redact)
	if strings.TrimSpace(code) == "" && !hasPOC {
		return nil
	}
	review := &db.ValidationAlertReview{ProblemCode: code, ProblemCodeTruncated: truncated, POCProvided: hasPOC}
	if hasPOC {
		hash := sha256.Sum256([]byte(poc))
		review.POCSHA256 = hex.EncodeToString(hash[:])
		review.POCText, review.POCTruncated = validationReviewText(poc, redact)
	}
	return review
}

func validationReviewText(raw string, redact func(string) string) (string, bool) {
	return validationTruncateText(redact(raw))
}

func validationTruncateText(raw string) (string, bool) {
	value := strings.ReplaceAll(raw, "\x00", "�")
	if len(value) <= maxValidationReviewBytes {
		return value, false
	}
	end := maxValidationReviewBytes
	for !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end], true
}

func validationReportRedactor(findings []validationSASTFinding) func(string) string {
	var secrets []string
	for _, f := range findings {
		if f.SecretValue != "" {
			secrets = append(secrets, f.SecretValue)
		}
	}
	// Prefer longer values when a shorter value is a prefix of another.
	sort.SliceStable(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	pairs := make([]string, 0, 2*len(secrets))
	for _, secret := range secrets {
		pairs = append(pairs, secret, "[已脱敏]")
	}
	return strings.NewReplacer(pairs...).Replace
}

func (f validationSASTFinding) context(appID, sourceAppID string, redact func(string) string, includeCategory bool) json.RawMessage {
	redactList := func(values []string) []string {
		out := make([]string, 0, len(values))
		for _, value := range values {
			out = append(out, redact(value))
		}
		return out
	}
	review := map[string]any{}
	if f.Status != "" {
		review["status"] = strings.TrimSpace(redact(f.Status))
	}
	if f.ExposureStatus != "" {
		review["exposureStatus"] = strings.TrimSpace(redact(f.ExposureStatus))
	}
	if f.Confidence != nil {
		review["confidence"] = *f.Confidence
	}
	flow := make([]validationSASTFlowNode, 0, len(f.CodeFlow))
	for _, node := range f.CodeFlow {
		node.File = strings.TrimSpace(redact(node.File))
		node.Role = strings.TrimSpace(redact(node.Role))
		if node.File != "" || node.Line != nil || node.Role != "" {
			flow = append(flow, node)
		}
	}
	mergedLocations := make([][]string, 0, len(f.MergedLocations))
	for _, locations := range f.MergedLocations {
		if locations == nil {
			mergedLocations = append(mergedLocations, nil)
		} else {
			mergedLocations = append(mergedLocations, redactList(locations))
		}
	}
	context := map[string]any{
		"locations":        redactList(f.Locations),
		"code_flow":        flow,
		"merged_from_ids":  redactList(f.MergedFromIDs),
		"merged_locations": mergedLocations,
		"static_review":    review,
	}
	if appID != "" {
		context["app_id"] = appID
	}
	if sourceAppID != "" {
		context["source_app_id"] = sourceAppID
	}
	if f.Severity != "" {
		context["original_severity"] = strings.TrimSpace(redact(f.Severity))
	}
	if includeCategory && strings.TrimSpace(f.CWE) != "" && f.Category != "" {
		context["category"] = strings.TrimSpace(redact(f.Category))
	}
	// All fields come from JSON strings, finite numbers, or typed slices.
	raw, _ := json.Marshal(context)
	return raw
}

func (s *Server) importValidationSASTReport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxValidationReportBytes)
	dec := json.NewDecoder(r.Body)
	var raw json.RawMessage
	err := dec.Decode(&raw)
	if err == nil {
		if err = dec.Decode(new(any)); err == io.EOF {
			err = nil
		} else if err == nil {
			err = errors.New("只允许一个 JSON 对象")
		}
	}
	if err != nil {
		var size *http.MaxBytesError
		if errors.As(err, &size) {
			writeErr(w, http.StatusRequestEntityTooLarge, "批量导入请求最多 5 MiB")
		} else {
			writeErr(w, http.StatusBadRequest, "批量导入请求无效："+err.Error())
		}
		return
	}
	// A raw report writes immediately. A request with a top-level report field
	// uses the original envelope, where submit must be explicit.
	in := validationSASTImport{Report: raw, Submit: true}
	var envelope struct {
		Report json.RawMessage `json:"report"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		writeErr(w, http.StatusBadRequest, "批量导入请求必须是 JSON 对象")
		return
	}
	if envelope.Report != nil {
		in = validationSASTImport{}
		wrapped := json.NewDecoder(bytes.NewReader(raw))
		wrapped.DisallowUnknownFields()
		if err := wrapped.Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "批量导入请求无效："+err.Error())
			return
		}
	}
	alerts, result, err := convertValidationSASTReport(in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !in.Submit {
		result.Totals["ready_to_import"] = len(alerts)
		writeJSON(w, http.StatusOK, result)
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	result.Submitted = true
	for i, alert := range alerts {
		if r.Context().Err() != nil {
			return
		}
		row := &result.Results[i]
		saved, created, err := pg.ImportValidationAlertWithReview(r.Context(), alert.ValidationAlertInput, alert.Review)
		switch {
		case errors.Is(err, db.ErrValidationConflict):
			row.Status, row.Error = "conflict", err.Error()
		case err != nil:
			log.Printf("[validation] SAST report import source=%q scan=%q finding=%q: %v", alert.Source, alert.ScanID, alert.ExternalID, err)
			row.Status, row.Error = "failed", "保存失败，可用相同报告重试"
		case created:
			row.Status, row.AlertID = "created", strconv.FormatInt(saved.ID, 10)
		default:
			row.Status, row.AlertID = "existing", strconv.FormatInt(saved.ID, 10)
		}
		result.Totals[row.Status]++
	}
	writeJSON(w, http.StatusOK, result)
}
