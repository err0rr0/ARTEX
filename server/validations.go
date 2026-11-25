package server

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

func (s *Server) registerValidationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/validation/alerts", s.importValidationAlert)
	mux.HandleFunc("POST /api/validation/imports/sast-report", s.importValidationSASTReport)
	mux.HandleFunc("GET /api/validation/alerts", s.listValidationAlerts)
	mux.HandleFunc("GET /api/validation/applications", s.listValidationApplications)
	mux.HandleFunc("GET /api/validation/alerts/{id}", s.getValidationAlert)
	mux.HandleFunc("DELETE /api/validation/alerts/{id}", s.deleteValidationAlert)
	mux.HandleFunc("POST /api/validation/alerts/{id}/reviews", s.saveValidationReview)
}

func validationHTTPError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, db.ErrValidationInvalid):
		status = 400
	case errors.Is(err, db.ErrValidationNotFound):
		status = 404
	case errors.Is(err, db.ErrValidationConflict):
		status = 409
	}
	if status == 500 {
		log.Printf("[validation] %v", err)
		writeErr(w, status, "白盒验证数据处理失败")
		return
	}
	writeErr(w, status, err.Error())
}

const maxValidationAlertBytes = 192 << 10

func validationDecode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxValidationAlertBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, 400, "请求 JSON 无效或超过 192KB: "+err.Error())
		return false
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		writeErr(w, 400, "只允许一个 JSON 对象")
		return false
	}
	return true
}
func (s *Server) importValidationAlert(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var in db.ValidationAlertInput
	if !validationDecode(w, r, &in) {
		return
	}
	a, created, err := pg.ImportValidationAlert(r.Context(), in)
	if err != nil {
		validationHTTPError(w, err)
		return
	}
	status := 200
	if created {
		status = 201
	}
	writeJSON(w, status, map[string]any{"alert": a, "created": created})
}
func (s *Server) listValidationAlerts(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	query := r.URL.Query()
	page := validationListPage(query.Get("page"))
	const limit = 20
	var appID *string
	if query.Has("app_id") {
		value := query.Get("app_id")
		appID = &value
	}
	items, total, err := pg.ListValidationAlertsByApplication(r.Context(), strings.TrimSpace(query.Get("source")), appID, page, limit)
	if err != nil {
		validationHTTPError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "page": page, "limit": limit})
}

func validationListPage(value string) int {
	page, _ := strconv.ParseInt(value, 10, 32)
	if page < 1 {
		return 1
	}
	return int(page)
}

func (s *Server) listValidationApplications(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	query := r.URL.Query()
	page := validationListPage(query.Get("page"))
	const limit = 20
	items, total, err := pg.ListValidationApplications(r.Context(), strings.TrimSpace(query.Get("source")), page, limit)
	if err != nil {
		validationHTTPError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "page": page, "limit": limit})
}
func (s *Server) getValidationAlert(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad id")
		return
	}
	a, err := pg.GetValidationAlert(r.Context(), id)
	if err != nil {
		validationHTTPError(w, err)
		return
	}
	runs, err := pg.ListValidationRuns(r.Context(), id)
	if err != nil {
		validationHTTPError(w, err)
		return
	}
	review, err := pg.GetValidationAlertReview(r.Context(), id)
	if err != nil {
		validationHTTPError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"alert": a, "runs": runs, "review": review})
}
func (s *Server) deleteValidationAlert(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "告警 ID 无效")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if err := pg.DeleteValidationAlert(r.Context(), id); err != nil {
		validationHTTPError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) saveValidationReview(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "告警 ID 无效")
		return
	}
	var input struct {
		Result string `json:"result"`
		Note   string `json:"note"`
	}
	if !validationDecode(w, r, &input) {
		return
	}
	var verdict string
	switch input.Result {
	case "vulnerability_exists":
		verdict = "confirmed"
	case "false_positive", "uncertain":
		verdict = input.Result
	default:
		writeErr(w, http.StatusBadRequest, "请选择有效的人工复核结论")
		return
	}
	run, err := pg.CreateValidationReview(r.Context(), id, verdict, input.Note)
	if err != nil {
		validationHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"run": run})
}
