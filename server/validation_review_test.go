package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestValidationManualReview(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL test DSN is not configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	const source = "__server_validation_manual_review_fixture"
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM validation_alerts WHERE source=$1`, source) })
	srv := &Server{m: &Manager{pg: pg}, jwtKey: []byte("validation-manual-review-test-key")}
	token, err := signJWT(srv.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	call := func(method, path, body string, authenticated bool, want int) []byte {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if authenticated {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("%s %s returned %d, want %d: %s", method, path, w.Code, want, w.Body.String())
		}
		return w.Body.Bytes()
	}
	raw := call(http.MethodPost, "/api/validation/alerts",
		`{"source":"`+source+`","scan_id":"fixture-job","external_id":"F-01","title":"配置待复核","vulnerability_type":"CWE-532","context":{"app_id":"fixture-app"}}`, true, http.StatusCreated)
	var imported struct {
		Alert struct {
			ID string `json:"id"`
		}
	}
	if err := json.Unmarshal(raw, &imported); err != nil || imported.Alert.ID == "" {
		t.Fatalf("invalid import response: %s (%v)", raw, err)
	}
	path := "/api/validation/alerts/" + imported.Alert.ID
	call(http.MethodPost, path+"/reviews", `{"result":"uncertain","note":"缺少证据"}`, false, http.StatusUnauthorized)
	call(http.MethodPost, path+"/reviews", `{"result":"invalid","note":"缺少证据"}`, true, http.StatusBadRequest)
	call(http.MethodPost, path+"/reviews", `{"result":"uncertain","note":"  "}`, true, http.StatusBadRequest)
	for _, result := range []string{"vulnerability_exists", "false_positive", "uncertain"} {
		call(http.MethodPost, path+"/reviews", `{"result":"`+result+`","note":"本地复核记录"}`, true, http.StatusCreated)
	}
	var detail struct {
		Runs []db.ValidationRun
	}
	if err := json.Unmarshal(call(http.MethodGet, path, "", true, http.StatusOK), &detail); err != nil ||
		len(detail.Runs) != 3 || detail.Runs[0].Verdict != "uncertain" ||
		detail.Runs[1].Verdict != "false_positive" || detail.Runs[2].Verdict != "confirmed" ||
		detail.Runs[0].Summary != "本地复核记录" {
		t.Fatalf("manual review history was not persisted: %+v (%v)", detail.Runs, err)
	}
}
