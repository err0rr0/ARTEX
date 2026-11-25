package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

var (
	ErrValidationInvalid  = errors.New("验证参数无效")
	ErrValidationConflict = errors.New("验证状态或告警内容冲突")
	ErrValidationNotFound = errors.New("验证记录不存在")
)

// Source-specific review data belongs in Context.
type ValidationAlertInput struct {
	Source            string          `json:"source"`
	ScanID            string          `json:"scan_id"`
	ExternalID        string          `json:"external_id"`
	Title             string          `json:"title"`
	VulnerabilityType string          `json:"vulnerability_type"`
	Severity          string          `json:"severity"`
	Repository        string          `json:"repository"`
	Commit            string          `json:"commit"`
	Module            string          `json:"module"`
	Description       string          `json:"description"`
	Context           json.RawMessage `json:"context"`
	TargetURL         string          `json:"target_url"`
}

type ValidationAlert struct {
	ValidationAlertInput
	ID              int64     `json:"id,string"`
	Readiness       string    `json:"readiness"`
	BlockingReasons []string  `json:"blocking_reasons"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// ValidationAlertReview is displayed in the alert detail and stays outside run snapshots.
type ValidationAlertReview struct {
	ProblemCode          string `json:"problem_code,omitempty"`
	ProblemCodeTruncated bool   `json:"problem_code_truncated,omitempty"`
	POCProvided          bool   `json:"poc_provided"`
	POCSHA256            string `json:"poc_sha256,omitempty"`
	POCText              string `json:"poc_text,omitempty"`
	POCTruncated         bool   `json:"poc_truncated,omitempty"`
}

type ValidationRun struct {
	ID         int64           `json:"id,string"`
	AlertID    int64           `json:"alert_id,string"`
	Snapshot   ValidationAlert `json:"snapshot"`
	Status     string          `json:"status"`
	Verdict    string          `json:"verdict"`
	Summary    string          `json:"summary"`
	CreatedAt  time.Time       `json:"created_at"`
	FinishedAt *time.Time      `json:"finished_at"`
}

func NormalizeValidationTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, "\r\n") {
		return "", fmt.Errorf("%w: target_url 必须是无账号、查询参数和片段的 HTTP(S) 服务入口", ErrValidationInvalid)
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("%w: target_url 端口无效", ErrValidationInvalid)
		}
	}
	u.Host = strings.ToLower(u.Host)
	if u.Path == "" {
		u.Path = "/"
	}
	if strings.ContainsAny(u.Path, "\\%\x00\r\n") || path.Clean(u.Path) != strings.TrimSuffix(u.Path, "/") && u.Path != "/" || strings.Contains(strings.ToLower(u.EscapedPath()), "%2f") || strings.Contains(strings.ToLower(u.EscapedPath()), "%5c") {
		return "", fmt.Errorf("%w: target_url 含歧义路径", ErrValidationInvalid)
	}
	// Keep the inherited representation for imported deployment addresses.
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return u.String(), nil
}

func (in *ValidationAlertInput) Normalize() error {
	in.Source = strings.TrimSpace(in.Source)
	in.ScanID = strings.TrimSpace(in.ScanID)
	in.ExternalID = strings.TrimSpace(in.ExternalID)
	in.Title = strings.TrimSpace(in.Title)
	in.VulnerabilityType = strings.TrimSpace(in.VulnerabilityType)
	in.Severity = strings.ToLower(strings.TrimSpace(in.Severity))
	if in.Severity == "" {
		in.Severity = "unknown"
	}
	if in.Source == "" || in.ExternalID == "" || in.Title == "" || in.VulnerabilityType == "" {
		return fmt.Errorf("%w: source、external_id、title、vulnerability_type 必填", ErrValidationInvalid)
	}
	if len(in.Source) > 80 || len(in.ScanID) > 160 || len(in.ExternalID) > 256 || len(in.Title) > 1000 || len(in.VulnerabilityType) > 160 || len(in.Repository) > 2000 || len(in.Commit) > 256 || len(in.Module) > 500 || len(in.Description) > 32000 {
		return fmt.Errorf("%w: 告警字段过长", ErrValidationInvalid)
	}
	if in.Severity != "unknown" && !ValidSeverity(in.Severity) {
		return fmt.Errorf("%w: severity 无效", ErrValidationInvalid)
	}
	if len(in.Context) == 0 || string(in.Context) == "null" {
		in.Context = json.RawMessage(`{}`)
	}
	var obj map[string]any
	if len(in.Context) > 128000 || json.Unmarshal(in.Context, &obj) != nil || obj == nil {
		return fmt.Errorf("%w: context 必须为不超过 128KB 的 JSON 对象", ErrValidationInvalid)
	}
	// Canonicalize JSON so whitespace and object key order do not defeat idempotency.
	in.Context, _ = json.Marshal(obj)
	target, err := NormalizeValidationTarget(in.TargetURL)
	if err != nil {
		return err
	}
	in.TargetURL = target
	return nil
}

func (a *ValidationAlert) readiness() {
	a.BlockingReasons = []string{}
	if a.TargetURL == "" {
		a.BlockingReasons = append(a.BlockingReasons, "missing_target_url")
	}
	if strings.TrimSpace(a.Description) == "" && string(a.Context) == "{}" {
		a.BlockingReasons = append(a.BlockingReasons, "missing_context")
	}
	a.Readiness = "ready"
	if len(a.BlockingReasons) > 0 {
		a.Readiness = "needs_input"
	}
}

type validationScanner interface{ Scan(...any) error }

const validationAlertCols = `id,input,target_url,created_at,updated_at`

func scanValidationAlert(row validationScanner) (*ValidationAlert, error) {
	var a ValidationAlert
	var raw []byte
	var target string
	if err := row.Scan(&a.ID, &raw, &target, &a.CreatedAt, &a.UpdatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &a.ValidationAlertInput); err != nil {
		return nil, err
	}
	a.TargetURL = target
	a.readiness()
	return &a, nil
}

func (d *DB) ImportValidationAlert(ctx context.Context, in ValidationAlertInput) (*ValidationAlert, bool, error) {
	return d.ImportValidationAlertWithReview(ctx, in, nil)
}

func (d *DB) ImportValidationAlertWithReview(ctx context.Context, in ValidationAlertInput, review *ValidationAlertReview) (*ValidationAlert, bool, error) {
	if err := in.Normalize(); err != nil {
		return nil, false, err
	}
	raw, _ := json.Marshal(in)
	hash := sha256.Sum256(raw)
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	a, err := scanValidationAlert(tx.QueryRowContext(ctx, `INSERT INTO validation_alerts(source,scan_id,external_id,title,severity,target_url,input,input_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(source,scan_id,external_id) DO NOTHING RETURNING `+validationAlertCols, in.Source, in.ScanID, in.ExternalID, in.Title, in.Severity, in.TargetURL, string(raw), hex.EncodeToString(hash[:])))
	created := err == nil
	if errors.Is(err, sql.ErrNoRows) {
		var stored string
		err = tx.QueryRowContext(ctx, `SELECT input_hash FROM validation_alerts WHERE source=$1 AND scan_id=$2 AND external_id=$3 FOR KEY SHARE`, in.Source, in.ScanID, in.ExternalID).Scan(&stored)
		if err != nil {
			return nil, false, err
		}
		if stored != hex.EncodeToString(hash[:]) {
			return nil, false, fmt.Errorf("%w: 同一来源/批次/外部 ID 的告警内容已改变，请使用新的扫描批次", ErrValidationConflict)
		}
		a, err = scanValidationAlert(tx.QueryRowContext(ctx, `SELECT `+validationAlertCols+` FROM validation_alerts WHERE source=$1 AND scan_id=$2 AND external_id=$3`, in.Source, in.ScanID, in.ExternalID))
	}
	if err != nil {
		return nil, false, err
	}
	if review != nil {
		// Identical reimports can add the review to older alerts with the original input hash.
		res, err := tx.ExecContext(ctx, `INSERT INTO validation_alert_reviews
			(alert_id,problem_code,problem_code_truncated,poc_provided,poc_sha256,poc_text,poc_truncated)
			VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(alert_id) DO UPDATE SET
			problem_code=CASE WHEN validation_alert_reviews.problem_code='' THEN EXCLUDED.problem_code ELSE validation_alert_reviews.problem_code END,
			problem_code_truncated=CASE WHEN validation_alert_reviews.problem_code='' THEN EXCLUDED.problem_code_truncated ELSE validation_alert_reviews.problem_code_truncated END,
			poc_provided=validation_alert_reviews.poc_provided OR EXCLUDED.poc_provided,
			poc_sha256=COALESCE(NULLIF(validation_alert_reviews.poc_sha256,''),EXCLUDED.poc_sha256),
			poc_text=COALESCE(NULLIF(validation_alert_reviews.poc_text,''),EXCLUDED.poc_text),
			poc_truncated=CASE WHEN validation_alert_reviews.poc_text='' THEN EXCLUDED.poc_truncated ELSE validation_alert_reviews.poc_truncated END
			WHERE validation_alert_reviews.poc_sha256='' OR EXCLUDED.poc_sha256=''
				OR validation_alert_reviews.poc_sha256=EXCLUDED.poc_sha256`,
			a.ID, review.ProblemCode, review.ProblemCodeTruncated, review.POCProvided, review.POCSHA256, review.POCText, review.POCTruncated)
		if err != nil {
			return nil, false, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, false, err
		}
		if n == 0 {
			return nil, false, fmt.Errorf("%w: 同一告警的 PoC 内容已改变，请使用新的扫描批次", ErrValidationConflict)
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, false, err
	}
	return a, created, nil
}

func (d *DB) GetValidationAlertReview(ctx context.Context, id int64) (*ValidationAlertReview, error) {
	var review ValidationAlertReview
	err := d.QueryRowContext(ctx, `SELECT problem_code,problem_code_truncated,poc_provided,poc_sha256,poc_text,poc_truncated
		FROM validation_alert_reviews WHERE alert_id=$1`, id).
		Scan(&review.ProblemCode, &review.ProblemCodeTruncated, &review.POCProvided, &review.POCSHA256, &review.POCText, &review.POCTruncated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &review, nil
}

func (d *DB) GetValidationAlert(ctx context.Context, id int64) (*ValidationAlert, error) {
	a, err := scanValidationAlert(d.QueryRowContext(ctx, `SELECT `+validationAlertCols+` FROM validation_alerts WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrValidationNotFound
	}
	return a, err
}

func (d *DB) ListValidationAlerts(ctx context.Context, source string, page, limit int) ([]*ValidationAlert, int, error) {
	return d.ListValidationAlertsByApplication(ctx, source, nil, page, limit)
}

// Group existing imports by their string context.app_id. Older imports and
// non-string values share the empty application group.
const validationAppID = `CASE WHEN jsonb_typeof(input->'context'->'app_id') = 'string'
	THEN btrim(input->'context'->>'app_id', E' \t\r\n') ELSE '' END`

type ValidationApplication struct {
	AppID string `json:"app_id"`
	Count int    `json:"count"`
}

func (d *DB) ListValidationApplications(ctx context.Context, source string, page, limit int) ([]ValidationApplication, int, error) {
	const filtered = ` FROM validation_alerts WHERE ($1='' OR source=$1)`
	var total int
	if err := d.QueryRowContext(ctx, `SELECT count(DISTINCT (`+validationAppID+`))`+filtered, source).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := d.QueryContext(ctx, `SELECT (`+validationAppID+`) AS app_id, count(*)`+filtered+
		` GROUP BY 1 ORDER BY ((`+validationAppID+`)=''), 1 LIMIT $2 OFFSET $3`, source, limit, (page-1)*limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	apps := []ValidationApplication{}
	for rows.Next() {
		var app ValidationApplication
		if err := rows.Scan(&app.AppID, &app.Count); err != nil {
			return nil, 0, err
		}
		apps = append(apps, app)
	}
	return apps, total, rows.Err()
}

func (d *DB) ListValidationAlertsByApplication(ctx context.Context, source string, appID *string, page, limit int) ([]*ValidationAlert, int, error) {
	const filtered = ` FROM validation_alerts WHERE ($1='' OR source=$1) AND ($2::text IS NULL OR (` + validationAppID + `)=$2)`
	var total int
	if err := d.QueryRowContext(ctx, `SELECT count(*)`+filtered, source, appID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := d.QueryContext(ctx, `SELECT `+validationAlertCols+filtered+` ORDER BY id DESC LIMIT $3 OFFSET $4`,
		source, appID, limit, (page-1)*limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*ValidationAlert{}
	for rows.Next() {
		a, err := scanValidationAlert(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

func (d *DB) DeleteValidationAlert(ctx context.Context, id int64) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Serialize with review creation and protect active records from older versions.
	var lockedID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM validation_alerts WHERE id=$1 FOR UPDATE`, id).Scan(&lockedID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrValidationNotFound
	}
	if err != nil {
		return err
	}
	var active bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM validation_runs WHERE alert_id=$1 AND status IN ('pending','running'))`, id).Scan(&active)
	if err != nil {
		return err
	}
	if active {
		return fmt.Errorf("%w: 此告警仍有关联的进行中记录", ErrValidationConflict)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM validation_alerts WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit()
}

const validationRunCols = `id,alert_id,snapshot,status,verdict,summary,created_at,finished_at`

func scanValidationRun(row validationScanner) (*ValidationRun, error) {
	var r ValidationRun
	var snapshot []byte
	if err := row.Scan(&r.ID, &r.AlertID, &snapshot, &r.Status, &r.Verdict, &r.Summary, &r.CreatedAt, &r.FinishedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(snapshot, &r.Snapshot); err != nil {
		return nil, err
	}
	return &r, nil
}

func (d *DB) CreateValidationReview(ctx context.Context, alertID int64, verdict, note string) (*ValidationRun, error) {
	switch verdict {
	case "confirmed", "false_positive", "uncertain":
	default:
		return nil, fmt.Errorf("%w: 请选择有效的人工复核结论", ErrValidationInvalid)
	}
	note = strings.TrimSpace(note)
	if note == "" || len(note) > 2000 || strings.ContainsRune(note, 0) {
		return nil, fmt.Errorf("%w: 复核说明必填且不能超过 2000 字节", ErrValidationInvalid)
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	alert, err := scanValidationAlert(tx.QueryRowContext(ctx, `SELECT `+validationAlertCols+` FROM validation_alerts WHERE id=$1 FOR UPDATE`, alertID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrValidationNotFound
	}
	if err != nil {
		return nil, err
	}
	snapshot, err := json.Marshal(alert)
	if err != nil {
		return nil, err
	}
	run, err := scanValidationRun(tx.QueryRowContext(ctx, `INSERT INTO validation_runs
		(alert_id,snapshot,status,verdict,summary,request_budget,timeout_seconds,finished_at)
		VALUES ($1,$2,'completed',$3,$4,1,30,now()) RETURNING `+validationRunCols, alertID, string(snapshot), verdict, note))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return run, nil
}

func (d *DB) ListValidationRuns(ctx context.Context, id int64) ([]*ValidationRun, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+validationRunCols+` FROM validation_runs WHERE alert_id=$1 ORDER BY id DESC LIMIT 100`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ValidationRun{}
	for rows.Next() {
		r, err := scanValidationRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
