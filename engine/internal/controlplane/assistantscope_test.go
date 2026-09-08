package controlplane

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/assistant"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
)

// THE ASSISTANT, FOR A PROVIDER WHO PICKED A CUSTOMER.
//
// The console's customer selector puts ?tenant= on every request its funnel
// sends, and the SOC route stands over the result saying every panel below is
// that customer's data. The assistant was the last surface under that banner
// that answered about a different one: this handler read no tenant, so the
// Runner was built from the session cookie alone and its tool calls reached the
// console's own read endpoints naming no customer — which authorizeRead
// resolves to the account's DEFAULT customer (authz.DefaultTenant). A provider
// who had switched to customer B asked a question and got a confident paragraph
// assembled out of customer A's telemetry.
//
// These tests pin both halves, as the enrichment scope tests do for the panels:
// the parameter is HONOURED all the way down to the tool call, and honouring it
// widens nobody's reach.

// fakeModel is an inference endpoint that asks for one tool and then answers.
// Deterministic, because an assistant tested against a live model is a test
// whose result depends on someone else's deployment.
func fakeModel(t *testing.T) *httptest.Server {
	t.Helper()
	turn := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		turn++
		w.Header().Set("Content-Type", "application/json")
		if turn == 1 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[` +
				`{"id":"1","type":"function","function":{"name":"list_alerts","arguments":"{}"}}]}}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"One alert, on web-01."}}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// assistantServer wires a control plane whose assistant is configured and whose
// tools read a recording stand-in for its own API. The bearer admin is the only
// principal a handler test can present — the production identity path is an
// OIDC session — and it is cross-tenant, which is exactly the persona this
// defect was about.
func assistantServer(t *testing.T) (*Server, *authz.MemAuditor, *[]url.Values) {
	t.Helper()
	var reads []url.Values
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads = append(reads, r.URL.Query())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(console.Close)

	t.Setenv("ASSISTANT_TEST_KEY", "k")
	aud := authz.NewMemAuditor()
	s := &Server{auditor: aud}
	s.cfg.AdminToken = "admin-secret"
	s.cfg.Logf = func(string, ...any) {}
	s.cfg.Assistant = assistant.Config{
		BaseURL:      fakeModel(t).URL,
		Model:        "test-model",
		APIKeyEnv:    "ASSISTANT_TEST_KEY",
		Timeout:      5 * time.Second,
		RunBudget:    10 * time.Second,
		MaxToolCalls: 2,
	}
	// selfBaseURL keeps only the port and dials 127.0.0.1, so the recording
	// console has to be reached the same way the real loopback read is.
	s.selfAddr = console.Listener.Addr().String()
	return s, aud, &reads
}

func askAs(t *testing.T, s *Server, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"agent":"ask","question":"anything on fire?"}`))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.handleAssistantAsk(w, r)
	return w
}

// TestAssistantToolCallsReadTheCustomerTheAskNamed is the defect itself: the
// answer must be built out of the customer the console named, not out of the
// one the server resolves for a request that names none.
func TestAssistantToolCallsReadTheCustomerTheAskNamed(t *testing.T) {
	s, _, reads := assistantServer(t)

	w := askAs(t, s, "/api/assistant/ask?tenant=globex", "admin-secret")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var ans map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &ans); err != nil {
		t.Fatalf("decoding the answer: %v", err)
	}
	if ans["grounded"] != true {
		t.Fatalf("the answer was not grounded, so no tool call was made: %v", ans)
	}
	if len(*reads) == 0 {
		t.Fatal("the assistant read nothing; there is no request to check the customer on")
	}
	for i, q := range *reads {
		if got := q.Get("tenant"); got != "globex" {
			t.Fatalf("tool read %d named tenant %q, want globex — the assistant answered a question "+
				"about one customer out of another customer's telemetry", i, got)
		}
	}
}

// A CROSS-TENANT ASK IS RECORDED. Reading a customer's alerts through the
// assistant is reading their data, and the operator trail exists so a customer
// can ask who from the provider opened their estate — an ask that answers
// without a row is one they cannot see.
func TestCrossTenantAskIsAudited(t *testing.T) {
	s, aud, _ := assistantServer(t)

	if w := askAs(t, s, "/api/assistant/ask?tenant=globex", "admin-secret"); w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var found *authz.AuditRecord
	for _, rec := range aud.Records() {
		if rec.Tenant == "globex" && rec.Action == string(authz.ActionRead) && rec.Subject == "admin" {
			hit := rec
			found = &hit
			break
		}
	}
	if found == nil {
		t.Fatalf("a provider asked the assistant about globex and no record was written: %v", aud.Records())
	}
	if !found.CrossTenant || !found.Allowed {
		t.Fatalf("record = %+v, want an allowed cross-tenant read", *found)
	}
}

// A principal that resolves to NO customer is refused before a token is spent.
//
// The break-glass bearer token carries no tenant, so authz.DefaultTenant
// answers "" for it and every other read on this server answers 400. The ask
// used to run anyway: the tool calls each failed on the same 400 and the run
// came back as the ungrounded refusal, having driven a full tool-calling loop
// against a paid inference endpoint to get there.
func TestAskWithNoResolvableCustomerIsRefusedBeforeTheModelIsCalled(t *testing.T) {
	s, _, reads := assistantServer(t)

	w := askAs(t, s, "/api/assistant/ask", "admin-secret")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 — the same answer every other read gives a principal that "+
			"names no tenant and has none stamped on it", w.Code)
	}
	if len(*reads) != 0 {
		t.Fatalf("the refused ask still read %d endpoint(s)", len(*reads))
	}
}

// An unauthenticated ask is still refused, and still in the shape the console
// parses. The gate exists because an unauthenticated caller could never obtain
// data — the tool calls simply failed — but could still drive a tool-calling
// loop against a paid inference endpoint.
func TestUnauthenticatedAskIsStillRefusedAsJSON(t *testing.T) {
	s, _, _ := assistantServer(t)

	w := askAs(t, s, "/api/assistant/ask?tenant=globex", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["error"] == "" {
		t.Fatalf("401 body = %q, want the JSON error the console reads", w.Body.String())
	}
}

// HONOURING THE PARAMETER MUST NOT WIDEN ANYONE.
//
// A tenant-bound analyst naming another customer is refused exactly as they are
// on every other read: a 404, which does not confirm whether that customer
// exists (tenant-isolation-invariant §6 side channels). A 403 would answer the
// question the refusal exists to withhold.
//
// Driven through authorizeReadAs — the function assistantScope resolves through
// — rather than through the handler, because the identity path that runs on the
// estate is an OIDC session no test can construct, and the only principal a
// handler test can present is the break-glass bearer token, which is
// cross-tenant and so is never the one refused. The AST test below is what
// binds this to the assistant's own handlers.
func TestTenantBoundOperatorCannotAskAboutAnotherCustomer(t *testing.T) {
	for _, path := range []string{
		"/api/assistant/ask?tenant=globex",
		"/api/assistant/stream?tenant=globex",
	} {
		s, aud, _ := assistantServer(t)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"agent":"ask"}`))

		tenant, ok := s.authorizeReadAs(w, r, keycloakPrincipal("op@acme", "acme-corp", authz.RoleTenantAnalyst))
		if ok {
			t.Fatalf("%s: an acme analyst asked the assistant about %q", path, tenant)
		}
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s: status %d, want 404 — anything else confirms the customer exists", path, w.Code)
		}
		if len(aud.Records()) == 0 {
			t.Fatalf("%s: a refused cross-tenant attempt was not recorded; a denied attempt is the "+
				"more interesting of the two records", path)
		}
	}
}

// assistantAskHandlers are the two entry points that spend inference budget on
// one customer's telemetry. The capability read is deliberately absent: it
// reports what THIS DEPLOYMENT has configured — a model name and an agent list
// — which is the same answer for every customer and belongs to none.
var assistantAskHandlers = []string{"handleAssistantAsk", "handleAssistantStream"}

// TestBothAssistantAsksUseTheSharedGate traces the fix from the other end.
//
// The refusal test above proves what authorizeReadAs does, not that these
// handlers reach it — and the defect was precisely a handler with its own
// weaker gate (authenticate, then trust the session for scope) that looked
// correct in isolation and ignored the parameter the console sends. A private
// resolution is the only shape this can come back in, so it is the shape that
// is pinned. The streaming path is included because streaming is where a rule
// like this is easiest to lose: it is a second copy of the same handler.
func TestBothAssistantAsksUseTheSharedGate(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return fi.Name() == "assistant.go"
	}, 0)
	if err != nil {
		t.Fatalf("parsing assistant.go: %v", err)
	}
	want := map[string]bool{}
	for _, name := range assistantAskHandlers {
		want[name] = true
	}
	// assistantScope is the gate; it resolves through authorizeReadAs, which
	// this test also checks so the gate cannot be hollowed out into a bare
	// authentication check while keeping its name.
	gateResolves := false
	gated := map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, isFunc := decl.(*ast.FuncDecl)
				if !isFunc || fn.Body == nil {
					continue
				}
				if fn.Name.Name == "assistantScope" {
					ast.Inspect(fn.Body, func(n ast.Node) bool {
						if sel, isSel := n.(*ast.SelectorExpr); isSel && sel.Sel.Name == "authorizeReadAs" {
							gateResolves = true
						}
						return true
					})
				}
				if !want[fn.Name.Name] {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if sel, isSel := n.(*ast.SelectorExpr); isSel && sel.Sel.Name == "assistantScope" {
						gated[fn.Name.Name] = true
					}
					return true
				})
			}
		}
	}
	if !gateResolves {
		t.Error("assistantScope no longer resolves the customer through authorizeReadAs, so an ask is " +
			"no longer authorized and audited the way every other read of that customer is")
	}
	var missing []string
	for _, name := range assistantAskHandlers {
		if !gated[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("these assistant entry points do not go through assistantScope, so ?tenant= is inert "+
			"on them and the console's customer selector does not reach the assistant: %s",
			strings.Join(missing, ", "))
	}
}

// streamAs is askAs against the STREAMING handler. Same body, same bearer, same
// recorder — only the entry point differs, which is the whole point below.
func streamAs(t *testing.T, s *Server, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"agent":"ask","question":"anything on fire?"}`))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.handleAssistantStream(w, r)
	return w
}

// THE STREAMING PATH IS THE ONE THE CONSOLE ACTUALLY USES, and until this test
// existed nothing pinned that its resolved customer reached the tool loop.
//
// TestBothAssistantAsksUseTheSharedGate proves both handlers CALL the gate, and
// TestAssistantToolCallsReadTheCustomerTheAskNamed proves the non-streaming
// answer is built out of the right customer's telemetry — but neither would
// notice handleAssistantStream resolving the tenant correctly and then failing
// to hand it to the Runner. Blanking Tenant on the streaming handler alone left
// the whole package green, which is a guard one layer short of the path every
// operator takes: the console asks through /api/assistant/stream and reads the
// answer as it is written.
//
// Asserted on the tool reads rather than on the frames, for the same reason the
// ask test is: the frames are what the model said, and the defect is which
// customer's rows it was allowed to say it about.
func TestStreamingAskAlsoReadsTheCustomerItNamed(t *testing.T) {
	s, _, reads := assistantServer(t)

	w := streamAs(t, s, "/api/assistant/stream?tenant=globex", "admin-secret")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if len(*reads) == 0 {
		t.Fatal("the streamed assistant read nothing; there is no request to check the customer on")
	}
	for i, q := range *reads {
		if got := q.Get("tenant"); got != "globex" {
			t.Fatalf("streamed tool read %d named tenant %q, want globex — the path the console "+
				"actually uses answered about one customer out of another's telemetry", i, got)
		}
	}
}

// The refusal must match on the streaming path too, and this is the one an
// unauthenticated caller meets.
//
// NOT asserted here, because it is not true and the attempt was instructive: a
// cross-tenant admin naming a customer that does not exist is NOT refused. That
// principal may reach any customer, and this control plane deliberately answers
// an unknown tenant with an empty read rather than a 404 — a refusal that
// varied by whether the name existed would confirm the MSSP's customer list to
// anyone able to guess at it. The reachability refusal belongs to a
// tenant-bound principal, and TestTenantBoundOperatorCannotAskAboutAnotherCustomer
// already drives it through authorizeReadAs (the estate's identity path is an
// OIDC session no handler test can construct).
//
// What IS the streaming path's own refusal: a caller with no principal at all
// must be turned away before the model is reached, exactly as the non-streaming
// ask is — an SSE handler that starts writing frames before it authenticates
// has already leaked the shape of the answer.
func TestUnauthenticatedStreamIsRefusedBeforeTheModelIsCalled(t *testing.T) {
	s, _, reads := assistantServer(t)

	w := streamAs(t, s, "/api/assistant/stream?tenant=globex", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401 — an unauthenticated stream was served: %s", w.Code, w.Body.String())
	}
	if len(*reads) != 0 {
		t.Fatalf("the unauthenticated stream read %d time(s) before it was refused", len(*reads))
	}
}
