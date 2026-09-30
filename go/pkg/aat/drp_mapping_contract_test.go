package aat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type drpMappingEntry struct {
	SourceSurface  string  `json:"source_surface"`
	SourcePath     string  `json:"source_path"`
	Classification string  `json:"classification"`
	DRPPath        *string `json:"drp_path"`
	Rationale      string  `json:"rationale"`
}

type drpMappingDocument struct {
	ProfileID string `json:"profile_id"`
	Status    string `json:"status"`
	DRP       struct {
		Document           string `json:"document"`
		FormalIETFStanding bool   `json:"formal_ietf_standing"`
	} `json:"drp"`
	AATSource struct {
		ImplementationDocument    string `json:"implementation_document"`
		AdditionalProfileDocument string `json:"additional_profile_document"`
		AdditionalProfile         string `json:"additional_profile"`
		LiveDocumentObserved      string `json:"live_document_observed"`
		FormalIETFStanding        bool   `json:"formal_ietf_standing"`
		MigrationIssue            string `json:"migration_issue"`
	} `json:"aat_source"`
	Classifications      []string          `json:"classifications"`
	SecurityRequirements map[string]string `json:"security_requirements"`
	Entries              []drpMappingEntry `json:"entries"`
}

func loadDRPMapping(t *testing.T) drpMappingDocument {
	t.Helper()
	path := filepath.Join("..", "..", "..", "docs", "specs", "ardur-drp-mapping-v0.1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read DRP mapping: %v", err)
	}
	var document drpMappingDocument
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode DRP mapping: %v", err)
	}
	return document
}

func jsonTaggedFields(t reflect.Type, prefix string) []string {
	var fields []string
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := strings.Split(field.Tag.Get("json"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		fields = append(fields, prefix+tag)
	}
	return fields
}

func mappingPaths(document drpMappingDocument, surface string) []string {
	var paths []string
	for _, entry := range document.Entries {
		if entry.SourceSurface == surface {
			paths = append(paths, entry.SourcePath)
		}
	}
	sort.Strings(paths)
	return paths
}

func requireSamePaths(t *testing.T, got, want []string) {
	t.Helper()
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mapping coverage mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestDRPMappingCoversDelegationGrantWireFields(t *testing.T) {
	document := loadDRPMapping(t)

	expected := jsonTaggedFields(reflect.TypeOf(Token{}), "")
	expected = append(expected, jsonTaggedFields(reflect.TypeOf(ConfirmationKey{}), "cnf.")...)
	expected = append(expected, jsonTaggedFields(reflect.TypeOf(AuthorizationDetail{}), "authorization_details[].")...)
	expected = append(expected, jsonTaggedFields(
		reflect.TypeOf(Constraint{}),
		"authorization_details[].tools.*.*.",
	)...)
	expected = append(expected,
		"mission_ref.uri",
		"mission_ref.mission_digest",
		"reserved_budget_share",
		"authorization_details[].tools.*.*.bucket",
		"authorization_details[].tools.*.*.max_share",
		"authorization_details[].tools.*.*.unit",
	)

	requireSamePaths(t, mappingPaths(document, "delegation_grant"), expected)
}

func TestDRPMappingCoversExecutionReceiptV02Schema(t *testing.T) {
	document := loadDRPMapping(t)
	path := filepath.Join("..", "..", "..", "docs", "specs", "execution-receipt-v0.2.schema.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read receipt schema: %v", err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("decode receipt schema: %v", err)
	}
	expected := make([]string, 0, len(schema.Properties))
	for name := range schema.Properties {
		expected = append(expected, name)
	}
	requireSamePaths(t, mappingPaths(document, "execution_receipt_v0.2"), expected)
}

func TestDRPMappingContractIsCompleteAndFailClosed(t *testing.T) {
	document := loadDRPMapping(t)
	if document.ProfileID != "ardur.drp-mapping.v0.1" {
		t.Fatalf("unexpected profile ID %q", document.ProfileID)
	}
	if document.Status != "mapping-only" {
		t.Fatalf("unexpected mapping status %q", document.Status)
	}
	if document.DRP.Document != "draft-nelson-agent-delegation-receipts-10" {
		t.Fatalf("mapping must pin draft-10, got %q", document.DRP.Document)
	}
	if document.DRP.FormalIETFStanding {
		t.Fatal("individual DRP draft must not be represented as having formal IETF standing")
	}
	if document.AATSource.ImplementationDocument !=
		"draft-niyikiza-oauth-attenuating-agent-tokens-00" {
		t.Fatalf("unexpected implemented AAT revision %q", document.AATSource.ImplementationDocument)
	}
	if document.AATSource.AdditionalProfileDocument !=
		"draft-niyikiza-oauth-attenuating-agent-tokens-01" {
		t.Fatalf("unexpected additional AAT profile revision %q", document.AATSource.AdditionalProfileDocument)
	}
	if document.AATSource.AdditionalProfile != DGProfileV02 {
		t.Fatalf("unexpected additional AAT profile %q", document.AATSource.AdditionalProfile)
	}
	if document.AATSource.LiveDocumentObserved !=
		"draft-niyikiza-oauth-attenuating-agent-tokens-01" {
		t.Fatalf("unexpected observed AAT revision %q", document.AATSource.LiveDocumentObserved)
	}
	if document.AATSource.FormalIETFStanding {
		t.Fatal("individual AAT draft must not be represented as having formal IETF standing")
	}
	if document.AATSource.MigrationIssue != "https://github.com/ArdurAI/ardur-evidence/issues/246" {
		t.Fatalf("unexpected AAT migration issue %q", document.AATSource.MigrationIssue)
	}

	allowedClassifications := map[string]bool{
		"mapped":       true,
		"extension":    true,
		"out_of_scope": true,
	}
	seen := make(map[string]bool, len(document.Entries))
	for _, entry := range document.Entries {
		key := entry.SourceSurface + "\x00" + entry.SourcePath
		if seen[key] {
			t.Fatalf("duplicate mapping entry for %s %s", entry.SourceSurface, entry.SourcePath)
		}
		seen[key] = true
		if !allowedClassifications[entry.Classification] {
			t.Fatalf("unknown classification %q for %s", entry.Classification, entry.SourcePath)
		}
		if entry.Rationale == "" {
			t.Fatalf("missing rationale for %s %s", entry.SourceSurface, entry.SourcePath)
		}
		if entry.Classification != "out_of_scope" &&
			(entry.DRPPath == nil || *entry.DRPPath == "") {
			t.Fatalf("missing target path for %s %s", entry.SourceSurface, entry.SourcePath)
		}
	}

	requiredSecurityRules := []string{
		"draft_status_acknowledged",
		"external_trust_anchor_required",
		"canonical_signing_input",
		"full_transitive_chain_verification",
		"parent_denials_preserved",
		"child_time_window_contained",
		"widening_rejected",
		"unknown_critical_extension_rejected",
		"tri_state_extension",
		"no_redelegation",
		"bounded_redelegation",
		"denied_redelegation",
		"revocation_freshness",
		"strict_action_subset",
		"finite_scope_universe_required",
		"delegation_log_anchor_required",
		"tsa_evidence_required",
		"p256_profile_selected",
	}
	for _, rule := range requiredSecurityRules {
		if document.SecurityRequirements[rule] == "" {
			t.Fatalf("missing security requirement %q", rule)
		}
	}
}
