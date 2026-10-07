package api

// Generative property tests for GET /v1/net-policies with fixed seeds. A
// deterministic generator builds legal and illegal query strings around a
// fixed pool of registered samples; every expectation is derived independently
// from the decoded conditions and the sample pool — never from another query's
// response — and compared against the full records in order-ascending
// sequence. The seeds are constants, so the same cases run in every `go test`
// invocation and any failure reproduces from the printed seed, raw query,
// expected and actual response. Each test function owns its router and
// database, keeping the groups independent of each other and of every
// pre-existing test.

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"github.com/Bob-xisuke/orb-netpolicy-guard/internal/store"
)

// generativeSample is one registered record the generated queries filter
// against: the decoded conditions plus the verbatim registration response.
type generativeSample struct {
	namespace string
	label     string
	record    map[string]any
}

const (
	generativeAllowRule = `[{"direction": "ingress", "action": "allow", "ports": [80, 80]}]`
	generativeDenyRule  = `[{"direction": "ingress", "action": "deny", "ports": [80, 90]}]`
)

// generativeSamplePool is the fixed sample set: the same label across
// namespaces ("tier=backend", the combined special label), the same namespace
// with different labels ("payments"), non-blank values composed of Chinese,
// plus, semicolon, ampersand, percent and leading/trailing spaces, and a label
// holding the literal text "%2B". The last record clashes with the first on
// purpose so the pool carries a conflict=true flag. All strings are valid
// UTF-8; registration asserts it.
var generativeSamplePool = []struct {
	namespace, label string
	rules            string
	conflict         bool
}{
	{"payments", "tier=backend", generativeAllowRule, false},
	{"华北", "tier=backend", generativeAllowRule, false},
	{"payments", "tier=后端", generativeAllowRule, false},
	{"payments", " 华北+a;b&c% ", generativeAllowRule, false},
	{" 边缘 ", " 华北+a;b&c% ", generativeAllowRule, false},
	{"a+b;c&d%", "50%_off", generativeAllowRule, false},
	{"华北", " 边缘 label ", generativeAllowRule, false},
	{"pay ments", "a%2Bb", generativeAllowRule, false},
	{"payments", "tier=backend", generativeDenyRule, true},
}

// Fixed seeds: every generative case below derives from these constants, so
// the cases are identical on every run and a failure reproduces as-is.
var (
	legalQuerySeeds   = []int64{2026100701, 2026100702, 2026100703}
	illegalQuerySeeds = []int64{2026100711, 2026100712, 2026100713}
)

// registerGenerativeSamples commits the fixed pool and returns each sample
// with its verbatim registration response for later comparisons.
func registerGenerativeSamples(t *testing.T, router *gin.Engine) []generativeSample {
	t.Helper()
	samples := make([]generativeSample, 0, len(generativeSamplePool))
	for i, spec := range generativeSamplePool {
		if !utf8.ValidString(spec.namespace) || !utf8.ValidString(spec.label) {
			t.Fatalf("sample %d is not valid UTF-8: %q / %q", i, spec.namespace, spec.label)
		}
		body := rawBoundaryBody(
			jsonStringLiteral(t, spec.namespace),
			jsonStringLiteral(t, fmt.Sprintf("rec-%02d", i+1)),
			jsonStringLiteral(t, spec.label),
			spec.rules, `{}`)
		record := registerCreated(t, router, body, int64(i+1), spec.conflict)
		samples = append(samples, generativeSample{spec.namespace, spec.label, record})
	}
	return samples
}

// expectedItems independently derives the matching records from the decoded
// conditions and the sample pool, in registration (order ascending) sequence.
// A nil result means no record matches and the query must answer 404.
func expectedItems(samples []generativeSample, namespace, label string) []map[string]any {
	var out []map[string]any
	for _, s := range samples {
		if namespace != "" && s.namespace != namespace {
			continue
		}
		if label != "" && s.label != label {
			continue
		}
		out = append(out, s.record)
	}
	return out
}

// Hex digit case for percent escapes: both cases are legal and must decode
// identically, so the generator exercises upper, lower and mixed encodings.
const (
	hexMixed = iota
	hexUpperOnly
	hexLowerOnly
)

// encodeQueryByte renders one byte as a percent escape with the hex digit
// case selected by mode (hexMixed picks randomly per escape).
func encodeQueryByte(rng *rand.Rand, mode int, b byte) string {
	digits := "0123456789ABCDEF"
	if mode == hexLowerOnly || (mode == hexMixed && rng.Intn(2) == 0) {
		digits = "0123456789abcdef"
	}
	return string([]byte{'%', digits[b>>4], digits[b&0x0f]})
}

// rawQuerySafe reports whether b can appear literally inside a query segment
// without changing how the service parses it: & splits segments, ; is
// rejected, + means space, % introduces an escape, and space/control bytes
// are always encoded.
func rawQuerySafe(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '-', '.', '_', '~', '!', '$', '\'', '(', ')', '*', ',', ':', '@', '=':
		return true
	}
	return false
}

// encodeQueryValue legally encodes a decoded parameter value: space becomes +
// or %20, safe ASCII stays literal or is escaped at random, and every other
// byte (+ ; & % and all multi-byte UTF-8) is percent-encoded exactly once.
func encodeQueryValue(rng *rand.Rand, mode int, value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r == ' ':
			if rng.Intn(2) == 0 {
				b.WriteByte('+')
			} else {
				b.WriteString(encodeQueryByte(rng, mode, ' '))
			}
		case r < 0x80 && rawQuerySafe(byte(r)) && rng.Intn(4) != 0:
			b.WriteByte(byte(r))
		case r < 0x80:
			b.WriteString(encodeQueryByte(rng, mode, byte(r)))
		default:
			for _, ub := range []byte(string(r)) {
				b.WriteString(encodeQueryByte(rng, mode, ub))
			}
		}
	}
	return b.String()
}

// encodeQueryName legally encodes a parameter name: letters stay literal or
// are percent-encoded at random, so "namespace" may appear as "%6Eamespace".
func encodeQueryName(rng *rand.Rand, mode int, name string) string {
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		if rng.Intn(4) == 0 {
			b.WriteString(encodeQueryByte(rng, mode, name[i]))
		} else {
			b.WriteByte(name[i])
		}
	}
	return b.String()
}

// Legal unknown parameters must be ignored. Names and values stay decodable
// and never collide with the known parameter names after decoding.
var (
	unknownParamNames  = []string{"verbose", "junk", "trace", "x-ignore"}
	unknownParamValues = []string{"true", "", "0", "+;&", "a b", "未知"}
)

func randomUnknownParam(rng *rand.Rand, mode int) string {
	name := unknownParamNames[rng.Intn(len(unknownParamNames))]
	value := unknownParamValues[rng.Intn(len(unknownParamValues))]
	return encodeQueryName(rng, mode, name) + "=" + encodeQueryValue(rng, mode, value)
}

// queryTweaks selects the legal transformations applied to a generated query:
// the hex case of percent escapes, injected legal unknown parameters and
// injected empty segments. Segment reordering is always applied.
type queryTweaks struct {
	hexMode  int
	unknown  bool
	emptySeg bool
}

// assembleQuery joins condition segments with random reordering plus the
// optional legal transformations — none of them may change the result.
func assembleQuery(rng *rand.Rand, segments []string, tweaks queryTweaks) string {
	if tweaks.unknown {
		for n := rng.Intn(3); n > 0; n-- {
			segments = append(segments, randomUnknownParam(rng, tweaks.hexMode))
		}
	}
	if tweaks.emptySeg {
		for n := rng.Intn(2) + 1; n > 0; n-- {
			segments = append(segments, "")
		}
	}
	rng.Shuffle(len(segments), func(i, j int) { segments[i], segments[j] = segments[j], segments[i] })
	query := strings.Join(segments, "&")
	if tweaks.emptySeg && rng.Intn(2) == 0 {
		query += "&"
	}
	return query
}

// legalQueryCase is one generated legal query together with the expectation
// derived from the conditions and the sample pool.
type legalQueryCase struct {
	query    string
	describe string
	want     []map[string]any // nil: expect 404 NetPolicyNotFoundError
}

// generateLegalQuery builds one legal query. Hit cases take conditions from a
// registered sample; miss cases take conditions guaranteed to match nothing.
// kind selects namespace-only, label-only or both (intersection).
func generateLegalQuery(rng *rand.Rand, samples []generativeSample, hit bool, kind int, tweaks queryTweaks) legalQueryCase {
	var namespace, label string
	if hit {
		s := samples[rng.Intn(len(samples))]
		switch kind {
		case 0:
			namespace = s.namespace
		case 1:
			label = s.label
		default:
			namespace, label = s.namespace, s.label
		}
	} else {
		namespace, label = missConditions(rng, samples, kind)
	}
	segments := make([]string, 0, 2)
	if namespace != "" {
		segments = append(segments,
			encodeQueryName(rng, tweaks.hexMode, "namespace")+"="+encodeQueryValue(rng, tweaks.hexMode, namespace))
	}
	if label != "" {
		segments = append(segments,
			encodeQueryName(rng, tweaks.hexMode, "label")+"="+encodeQueryValue(rng, tweaks.hexMode, label))
	}
	want := expectedItems(samples, namespace, label)
	if hit && len(want) == 0 {
		panic("unreachable: hit case produced an empty expectation")
	}
	return legalQueryCase{
		query:    assembleQuery(rng, segments, tweaks),
		describe: fmt.Sprintf("namespace=%q label=%q", namespace, label),
		want:     want,
	}
}

// missConditions derives decoded conditions guaranteed to match no sample:
// values near a registered one only by case or surrounding spaces, wholly
// unregistered values, or a registered namespace/label pair that never
// co-occurs on a single record.
func missConditions(rng *rand.Rand, samples []generativeSample, kind int) (namespace, label string) {
	for attempt := 0; attempt < 200; attempt++ {
		var ns, lb string
		switch kind {
		case 0:
			ns = missValue(rng, samples, false)
		case 1:
			lb = missValue(rng, samples, true)
		default:
			s := samples[rng.Intn(len(samples))]
			switch rng.Intn(3) {
			case 0:
				ns, lb = s.namespace, missValue(rng, samples, true)
			case 1:
				ns, lb = missValue(rng, samples, false), s.label
			default:
				ns = samples[rng.Intn(len(samples))].namespace
				lb = samples[rng.Intn(len(samples))].label
			}
		}
		if ns == "" && lb == "" {
			continue
		}
		if len(expectedItems(samples, ns, lb)) == 0 {
			return ns, lb
		}
	}
	return "missing-namespace", ""
}

// unregisteredValues are non-blank strings no sample uses for either field.
// "a%252Bb" decodes to the literal text "%252B" — one decoding layer above
// the registered "a%2Bb" label — and must stay a miss.
var unregisteredValues = []string{"missing", "没有登记", "un registered", "a%252Bb", "n/a"}

// missValue returns a non-blank value equal to no sample for the field:
// either a near miss of a registered value (letter case or surrounding
// spaces) or a wholly unregistered string.
func missValue(rng *rand.Rand, samples []generativeSample, labelField bool) string {
	pool := map[string]bool{}
	for _, s := range samples {
		if labelField {
			pool[s.label] = true
		} else {
			pool[s.namespace] = true
		}
	}
	for attempt := 0; attempt < 200; attempt++ {
		var candidate string
		if rng.Intn(2) == 0 {
			s := samples[rng.Intn(len(samples))]
			base := s.namespace
			if labelField {
				base = s.label
			}
			misses := nearMisses(base)
			candidate = misses[rng.Intn(len(misses))]
		} else {
			candidate = unregisteredValues[rng.Intn(len(unregisteredValues))]
		}
		if strings.TrimSpace(candidate) != "" && !pool[candidate] {
			return candidate
		}
	}
	return "missing"
}

// nearMisses lists values close to base by letter case or surrounding spaces
// but never equal to it: non-blank values match verbatim, so these must miss.
func nearMisses(base string) []string {
	out := []string{" " + base, base + " "}
	if flipped := flipASCIICase(base); flipped != base {
		out = append(out, flipped)
	}
	if upper := strings.ToUpper(base); upper != base {
		out = append(out, upper)
	}
	if i := strings.Index(base, " "); i >= 0 {
		out = append(out, base[:i]+base[i+1:])
	}
	return out
}

func flipASCIICase(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 'a' + 'A')
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r - 'A' + 'a')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// badEscapeSuffixes are incomplete or non-hex percent escapes: appending any
// of them to a name or value makes the segment undecodable.
var badEscapeSuffixes = []string{"%", "%2", "%GG", "%zz", "%g0"}

// Illegal defect classes, one generator branch each.
const (
	defectBadEscapeValue = iota
	defectBadEscapeName
	defectBadEscapeUnknown
	defectSemicolon
	defectDuplicateKnown
	defectBlankCondition
	defectNoCondition
	defectClassCount
)

// generateIllegalQuery builds a query around conditions that would have
// matched committed samples, then breaks exactly one rule of the query
// grammar. For injected fragments position selects front, middle or back
// placement; defectBadEscapeUnknown puts the bad fragment in an unknown
// parameter. The whole query must be rejected with 400 and leak nothing.
func generateIllegalQuery(rng *rand.Rand, samples []generativeSample, class, position int) (target, describe string) {
	s := samples[rng.Intn(len(samples))]
	nsSeg := encodeQueryName(rng, hexMixed, "namespace") + "=" + encodeQueryValue(rng, hexMixed, s.namespace)
	labelSeg := encodeQueryName(rng, hexMixed, "label") + "=" + encodeQueryValue(rng, hexMixed, s.label)
	legal := []string{nsSeg}
	if rng.Intn(2) == 0 {
		legal = append(legal, labelSeg)
	}

	var bad string
	switch class {
	case defectBadEscapeValue:
		i := rng.Intn(len(legal))
		legal[i] += badEscapeSuffixes[rng.Intn(len(badEscapeSuffixes))]
		describe = "incomplete or non-hex escape in known value"
	case defectBadEscapeName:
		badName := []string{"namespace%", "namespace%2", "label%", "label%GG"}[rng.Intn(4)]
		bad = badName + "=" + encodeQueryValue(rng, hexMixed, "x")
		describe = "incomplete or non-hex escape in known name"
	case defectBadEscapeUnknown:
		bad = []string{"junk=%ZZ", "ju%nk=1", "trace=%", "junk=ab%2"}[rng.Intn(4)]
		describe = "bad escape in unknown parameter"
	case defectSemicolon:
		bad = []string{"junk=a;b", ";", "note=pay;ments"}[rng.Intn(3)]
		describe = "unescaped semicolon"
	case defectDuplicateKnown:
		// The duplicated parameter must actually be present: force both
		// conditions into the query, then repeat one of them under a literal
		// or percent-encoded spelling with the same or a different value.
		legal = []string{nsSeg, labelSeg}
		if rng.Intn(2) == 0 {
			dupName := []string{"namespace", "%6Eamespace", "namespac%65"}[rng.Intn(3)]
			dupValue := s.namespace
			if rng.Intn(2) == 0 {
				dupValue = "other-ns"
			}
			bad = dupName + "=" + encodeQueryValue(rng, hexMixed, dupValue)
		} else {
			dupName := []string{"label", "%6Cabel", "labe%6C"}[rng.Intn(3)]
			dupValue := s.label
			if rng.Intn(2) == 0 {
				dupValue = "other-label"
			}
			bad = dupName + "=" + encodeQueryValue(rng, hexMixed, dupValue)
		}
		describe = "duplicate known parameter"
	case defectBlankCondition:
		options := []string{
			"namespace=",
			"namespace=+",
			"label=%20%20",
			"namespace=%20&label=" + encodeQueryValue(rng, hexMixed, s.label),
		}
		return "/v1/net-policies?" + options[rng.Intn(len(options))], "empty or blank known condition"
	case defectNoCondition:
		options := []string{
			"/v1/net-policies",
			"/v1/net-policies?",
			"/v1/net-policies?&",
			"/v1/net-policies?verbose=true&junk=" + encodeQueryValue(rng, hexMixed, "+;&"),
			"/v1/net-policies?empty=&unknown=%20",
		}
		return options[rng.Intn(len(options))], "no known condition"
	}

	// Legal unknown parameters and empty segments around the defect must not
	// dilute the rejection.
	for n := rng.Intn(3); n > 0; n-- {
		legal = append(legal, randomUnknownParam(rng, hexMixed))
	}
	if rng.Intn(2) == 0 {
		legal = append(legal, "")
	}

	segments := legal
	if bad != "" {
		idx := 0
		switch position {
		case 1:
			idx = len(segments) / 2
		case 2:
			idx = len(segments)
		}
		segments = append(segments, "")
		copy(segments[idx+1:], segments[idx:])
		segments[idx] = bad
	}
	return "/v1/net-policies?" + strings.Join(segments, "&"), describe
}

// assertLegalQuery runs one generated legal query twice — identical input
// must reproduce identical output — and checks the response against the
// independently derived expectation: 404 with the published error shape on a
// miss, otherwise 200 with the full records in order-ascending sequence.
func assertLegalQuery(t *testing.T, router *gin.Engine, tc legalQueryCase) {
	t.Helper()
	target := "/v1/net-policies?" + tc.query
	recorder := doRequest(router, http.MethodGet, target, "")
	repeat := doRequest(router, http.MethodGet, target, "")
	if repeat.Code != recorder.Code || repeat.Body.String() != recorder.Body.String() {
		t.Fatalf("GET %s not reproducible:\nfirst  %d %s\nsecond %d %s",
			target, recorder.Code, recorder.Body.String(), repeat.Code, repeat.Body.String())
	}

	if tc.want == nil {
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("GET %s\nconditions %s\nwant 404 NetPolicyNotFoundError\ngot status %d body %s",
				target, tc.describe, recorder.Code, recorder.Body.String())
		}
		assertExactErrorShape(t, recorder, "NetPolicyNotFoundError")
		assertSafeErrorMessage(t, recorder)
		return
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %s\nconditions %s\nwant 200 with %d items\ngot status %d body %s",
			target, tc.describe, len(tc.want), recorder.Code, recorder.Body.String())
	}
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET %s: decode items: %v (body %s)", target, err, recorder.Body.String())
	}
	for i := 1; i < len(body.Items); i++ {
		prev, _ := body.Items[i-1]["order"].(float64)
		cur, _ := body.Items[i]["order"].(float64)
		if prev >= cur {
			t.Fatalf("GET %s\nitems not order-ascending: %v", target, body.Items)
		}
	}
	if !reflect.DeepEqual(body.Items, tc.want) {
		t.Fatalf("GET %s\nconditions %s\nwant items %v\ngot items %v",
			target, tc.describe, tc.want, body.Items)
	}
}

// assertRegistryUnchanged verifies every committed record — content, order
// and conflict flag — is exactly what its registration returned.
func assertRegistryUnchanged(t *testing.T, st *store.Store, samples []generativeSample) {
	t.Helper()
	records, err := st.List("", "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(records) != len(samples) {
		t.Fatalf("registry holds %d records, want the %d committed samples", len(records), len(samples))
	}
	for i, rec := range records {
		raw, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal record %d: %v", i, err)
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("decode record %d: %v", i, err)
		}
		if !reflect.DeepEqual(got, samples[i].record) {
			t.Fatalf("record %d changed after the query group:\n got %v\nwant %v", i, got, samples[i].record)
		}
	}
}

func sampleByLabel(t *testing.T, samples []generativeSample, label string) generativeSample {
	t.Helper()
	for _, s := range samples {
		if s.label == label {
			return s
		}
	}
	t.Fatalf("no sample with label %q", label)
	return generativeSample{}
}

// Legal generated queries keep the published semantics: every class of legal
// transformation (segment reorder, legal unknown parameters, empty segments,
// percent-escape hex case, single-pass decoding) runs with hit and miss fixed
// seeds, and each response is checked against the expectation derived from
// the conditions and the samples — full records, order ascending. The group
// ends by proving the registry is untouched and the next order is max+1.
func TestGetNetPoliciesGenerativeLegalQueries(t *testing.T) {
	router, st := newTestRouter(t)
	samples := registerGenerativeSamples(t, router)

	// Explicit anchors on top of the generated cases. + and %20 both mean
	// space and find the "pay ments" sample.
	encoded := sampleByLabel(t, samples, "a%2Bb")
	for _, target := range []string{
		"/v1/net-policies?namespace=pay+ments",
		"/v1/net-policies?namespace=pay%20ments",
	} {
		items := listItems(t, router, target)
		if want := []map[string]any{encoded.record}; !reflect.DeepEqual(items, want) {
			t.Fatalf("GET %s items = %v, want %v", target, items, want)
		}
	}
	// Parameters decode exactly once: %252B is the literal text "%2B" and
	// hits the sample storing that text; one more layer (%25252B decodes to
	// "%252B") is not registered and must miss.
	items := listItems(t, router, "/v1/net-policies?label=a%252Bb")
	if want := []map[string]any{encoded.record}; !reflect.DeepEqual(items, want) {
		t.Fatalf("GET label=a%%252Bb items = %v, want %v (parameters decode once)", items, want)
	}
	miss := doRequest(router, http.MethodGet, "/v1/net-policies?label=a%25252Bb", "")
	if miss.Code != http.StatusNotFound {
		t.Fatalf("GET label=a%%25252Bb status = %d, want %d: %s", miss.Code, http.StatusNotFound, miss.Body.String())
	}
	assertExactErrorShape(t, miss, "NetPolicyNotFoundError")
	// Case-only or space-only differences never hit a registered value.
	for _, target := range []string{
		"/v1/net-policies?namespace=PAYMENTS",
		"/v1/net-policies?namespace=+payments",
		"/v1/net-policies?namespace=payments+",
		"/v1/net-policies?label=TIER%3DBACKEND",
	} {
		recorder := doRequest(router, http.MethodGet, target, "")
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("GET %s status = %d, want %d: %s", target, recorder.Code, http.StatusNotFound, recorder.Body.String())
		}
		assertExactErrorShape(t, recorder, "NetPolicyNotFoundError")
	}
	// The shared label crosses namespaces; both conditions intersect.
	if want := expectedItems(samples, "", "tier=backend"); len(want) != 3 {
		t.Fatalf("pool anchor: label tier=backend spans %d records, want 3", len(want))
	} else if items := listItems(t, router, "/v1/net-policies?label=tier%3Dbackend"); !reflect.DeepEqual(items, want) {
		t.Fatalf("label-only items = %v, want %v", items, want)
	}
	if want := expectedItems(samples, "payments", "tier=backend"); len(want) != 2 {
		t.Fatalf("pool anchor: intersection holds %d records, want 2", len(want))
	} else if items := listItems(t, router, "/v1/net-policies?namespace=payments&label=tier%3Dbackend"); !reflect.DeepEqual(items, want) {
		t.Fatalf("intersection items = %v, want %v", items, want)
	}

	transforms := []struct {
		name      string
		tweaks    queryTweaks
		forceKind int // -1: every condition kind
	}{
		{"mixed hex case", queryTweaks{hexMode: hexMixed}, -1},
		{"uppercase hex escapes", queryTweaks{hexMode: hexUpperOnly}, -1},
		{"lowercase hex escapes", queryTweaks{hexMode: hexLowerOnly}, -1},
		{"legal unknown parameters", queryTweaks{hexMode: hexMixed, unknown: true}, -1},
		{"empty segments", queryTweaks{hexMode: hexMixed, emptySeg: true}, -1},
		{"segment reorder", queryTweaks{hexMode: hexMixed, unknown: true, emptySeg: true}, 2},
	}
	for _, seed := range legalQuerySeeds {
		rng := rand.New(rand.NewSource(seed))
		caseNo := 0
		run := func(hit bool, kind int, tweaks queryTweaks) {
			tc := generateLegalQuery(rng, samples, hit, kind, tweaks)
			name := fmt.Sprintf("seed-%d/case-%02d", seed, caseNo)
			caseNo++
			t.Run(name, func(t *testing.T) { assertLegalQuery(t, router, tc) })
		}
		// Every transformation class with hit and miss fixed seeds, across
		// namespace-only, label-only and intersecting conditions.
		for _, tr := range transforms {
			for _, hit := range []bool{true, false} {
				for kind := 0; kind < 3; kind++ {
					k := kind
					if tr.forceKind >= 0 {
						k = tr.forceKind
					}
					run(hit, k, tr.tweaks)
				}
			}
		}
		// Randomized mixed cases for volume.
		for i := 0; i < 20; i++ {
			run(rng.Intn(2) == 0, rng.Intn(3), queryTweaks{
				hexMode:  rng.Intn(3),
				unknown:  rng.Intn(2) == 0,
				emptySeg: rng.Intn(2) == 0,
			})
		}
	}

	// The whole group changed nothing: content, order and conflict flags are
	// intact, and the next registration takes the original max order + 1.
	assertRegistryUnchanged(t, st, samples)
	registerCreated(t, router,
		rawBoundaryBody(`"post-legal"`, `"fresh"`, `"post-legal"`, generativeAllowRule, `{}`),
		int64(len(samples)+1), false)
}

// Illegal generated queries are rejected wholesale: whatever the defect —
// incomplete or non-hex percent escape in a name or value, an unescaped
// semicolon, a decoded duplicate known parameter, an empty or blank known
// condition, or no known condition at all — and wherever the bad fragment
// sits (front, middle, back, or inside an unknown parameter), the response is
// 400 with exactly the published error shape and never a record that the
// remaining conditions would have matched. The registry stays untouched.
func TestGetNetPoliciesGenerativeRejectsIllegalQueries(t *testing.T) {
	router, st := newTestRouter(t)
	samples := registerGenerativeSamples(t, router)

	for _, seed := range illegalQuerySeeds {
		rng := rand.New(rand.NewSource(seed))
		for class := 0; class < defectClassCount; class++ {
			positions := 3
			if class >= defectBlankCondition {
				positions = 1 // whole-query defects carry no fragment position
			}
			for pos := 0; pos < positions; pos++ {
				target, describe := generateIllegalQuery(rng, samples, class, pos)
				t.Run(fmt.Sprintf("seed-%d/class-%d/pos-%d", seed, class, pos), func(t *testing.T) {
					recorder := doRequest(router, http.MethodGet, target, "")
					if recorder.Code != http.StatusBadRequest {
						t.Fatalf("GET %s\ndefect: %s\nwant 400 InvalidNetPolicyInputError\ngot status %d body %s",
							target, describe, recorder.Code, recorder.Body.String())
					}
					assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
					assertSafeErrorMessage(t, recorder)
				})
			}
		}
	}

	// The rejections leaked and changed nothing: content, order and conflict
	// flags are intact, and the next registration takes the original max
	// order + 1.
	assertRegistryUnchanged(t, st, samples)
	registerCreated(t, router,
		rawBoundaryBody(`"post-illegal"`, `"fresh"`, `"post-illegal"`, generativeAllowRule, `{}`),
		int64(len(samples)+1), false)
}
