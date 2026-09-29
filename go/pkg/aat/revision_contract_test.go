package aat

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func signTestPayload(t *testing.T, payload []byte, signerKey ed25519.PrivateKey) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: signerKey},
		(&jose.SignerOptions{}).WithHeader("alg", "EdDSA"),
	)
	if err != nil {
		t.Fatalf("creating test signer: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("signing test payload: %v", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serializing test payload: %v", err)
	}
	return compact
}

func signTestClaims(t *testing.T, claims map[string]interface{}, signerKey ed25519.PrivateKey) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshaling test claims: %v", err)
	}
	return signTestPayload(t, payload, signerKey)
}

func thumbprintIssuer(t *testing.T, publicKey ed25519.PublicKey) string {
	t.Helper()
	jwk := publicKeyToJWK(publicKey)
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("computing holder thumbprint: %v", err)
	}
	return "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" +
		base64.RawURLEncoding.EncodeToString(thumbprint)
}

func TestPoPJWTUsesDirectRFC8785CanonicalPayload(t *testing.T) {
	publicKey, privateKey := newKeyPair()
	now := time.Now()
	args := map[string]interface{}{
		"count": 1.0,
		"path":  "/tmp/report.json",
	}
	leaf := &Token{
		JWTID:        "leaf-canonical",
		TokenType:    AATTypeExecution,
		Confirmation: &ConfirmationKey{JWK: publicKeyToJWK(publicKey)},
	}

	compact, err := BuildPoPJWT(BuildPoPOpts{
		JWTID:  "pop-canonical",
		Now:    now,
		Leaf:   leaf,
		Tool:   "read_file",
		Args:   args,
		Signer: privateKey,
	})
	if err != nil {
		t.Fatalf("BuildPoPJWT failed: %v", err)
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("compact PoP has %d segments", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding PoP payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parsing PoP claims: %v", err)
	}
	canonical, err := canonicalizeJSON(claims)
	if err != nil {
		t.Fatalf("canonicalizing PoP claims: %v", err)
	}
	if string(payload) != string(canonical) {
		t.Fatalf("PoP payload is not RFC 8785 canonical:\n%s\nwant:\n%s", payload, canonical)
	}
	hta, ok := claims["hta"].(map[string]interface{})
	if !ok {
		t.Fatalf("hta is %T, want object", claims["hta"])
	}
	if !reflect.DeepEqual(hta, args) {
		t.Fatalf("hta = %#v, want direct args %#v", hta, args)
	}
	if _, wrapped := hta["args"]; wrapped {
		t.Fatal("hta must not use the old implementation-specific args wrapper")
	}
}

func TestVerifyPoPJWTRejectsNonCanonicalPayloadAndMissingJTI(t *testing.T) {
	publicKey, privateKey := newKeyPair()
	now := time.Now()
	leaf := &Token{
		JWTID:        "leaf-pop-validation",
		TokenType:    AATTypeExecution,
		Confirmation: &ConfirmationKey{JWK: publicKeyToJWK(publicKey)},
	}

	nonCanonical := []byte(fmt.Sprintf(
		`{"jti":"pop-noncanonical","iat":%d,"aat_id":"leaf-pop-validation","aat_tool":"read_file","hta":{"z":1,"a":2}}`,
		now.Unix(),
	))
	compact := signTestPayload(t, nonCanonical, privateKey)
	_, err := VerifyPoPJWT(
		leaf,
		"read_file",
		map[string]interface{}{"a": 2.0, "z": 1.0},
		compact,
		VerifyPoPOpts{Now: now},
	)
	if !errors.Is(err, ErrDenyStep7ANonCanonical) {
		t.Fatalf("non-canonical PoP error = %v, want ErrDenyStep7ANonCanonical", err)
	}

	claims := map[string]interface{}{
		"iat":      now.Unix(),
		"aat_id":   leaf.JWTID,
		"aat_tool": "read_file",
		"hta":      map[string]interface{}{},
	}
	canonical, err := canonicalizeJSON(claims)
	if err != nil {
		t.Fatalf("canonicalizing missing-jti fixture: %v", err)
	}
	compact = signTestPayload(t, canonical, privateKey)
	_, err = VerifyPoPJWT(leaf, "read_file", map[string]interface{}{}, compact, VerifyPoPOpts{Now: now})
	if !errors.Is(err, ErrDenyStep7AMissingJTI) {
		t.Fatalf("missing-jti PoP error = %v, want ErrDenyStep7AMissingJTI", err)
	}
}

func TestDraft01WireIsRejectedExplicitlyAtRootAndChild(t *testing.T) {
	anchorPublic, anchorPrivate := newKeyPair()
	holderPublic, holderPrivate := newKeyPair()
	childPublic, _ := newKeyPair()
	now := time.Now()
	authorization := simpleAuthorization(wildcardToolMap("read_file"))

	draft01RootClaims := map[string]interface{}{
		"jti":                   "draft01-root",
		"iss":                   "https://issuer.example",
		"iat":                   now.Unix(),
		"exp":                   now.Add(time.Hour).Unix(),
		"cnf":                   map[string]interface{}{"jwk": publicKeyToJWK(holderPublic)},
		"del_depth":             0,
		"del_max_depth":         2,
		"authorization_details": authorization,
	}
	draft01Root := &Token{Compact: signTestClaims(t, draft01RootClaims, anchorPrivate)}
	_, err := VerifyChain([]*Token{draft01Root}, [][]byte{anchorPublic}, "read_file", nil, "unused")
	if !errors.Is(err, ErrUnsupportedDraftRevision) {
		t.Fatalf("draft-01 root error = %v, want ErrUnsupportedDraftRevision", err)
	}

	root, err := IssueRoot(IssueRootOpts{
		JWTID:              "draft00-root",
		Issuer:             "https://issuer.example",
		Now:                now,
		ExpiresAt:          now.Add(time.Hour),
		TokenType:          AATTypeDelegation,
		MaxDelegationDepth: 2,
		HolderJWK:          publicKeyToJWK(holderPublic),
		Authorization:      authorization,
		Signer:             anchorPrivate,
	})
	if err != nil {
		t.Fatalf("IssueRoot failed: %v", err)
	}
	draft01ChildClaims := map[string]interface{}{
		"jti":                   "draft01-child",
		"iss":                   thumbprintIssuer(t, holderPublic),
		"iat":                   now.Unix(),
		"exp":                   now.Add(30 * time.Minute).Unix(),
		"cnf":                   map[string]interface{}{"jwk": publicKeyToJWK(childPublic)},
		"del_depth":             1,
		"del_max_depth":         2,
		"par_hash":              computeParentHash(root),
		"authorization_details": authorization,
	}
	draft01Child := &Token{Compact: signTestClaims(t, draft01ChildClaims, holderPrivate)}
	_, err = VerifyChain([]*Token{root, draft01Child}, [][]byte{anchorPublic}, "read_file", nil, "unused")
	if !errors.Is(err, ErrUnsupportedDraftRevision) {
		t.Fatalf("draft-01 child error = %v, want ErrUnsupportedDraftRevision", err)
	}
}

func TestDraft00RootChildGrandchildNarrowingAndSecurityBoundaries(t *testing.T) {
	anchorPublic, anchorPrivate := newKeyPair()
	rootHolderPublic, rootHolderPrivate := newKeyPair()
	childHolderPublic, childHolderPrivate := newKeyPair()
	leafHolderPublic, leafHolderPrivate := newKeyPair()
	now := time.Now().Add(-2 * time.Minute)

	rootAuthorization := simpleAuthorization(ToolMap{
		"read_file": {
			"path": &Constraint{ConstraintType: ConstraintTypeOneOf, Values: []interface{}{"/tmp/a", "/tmp/b"}},
		},
	})
	childAuthorization := simpleAuthorization(ToolMap{
		"read_file": {
			"path": &Constraint{ConstraintType: ConstraintTypeOneOf, Values: []interface{}{"/tmp/a"}},
		},
	})
	leafAuthorization := simpleAuthorization(ToolMap{
		"read_file": {
			"path": &Constraint{ConstraintType: ConstraintTypeExact, Value: "/tmp/a"},
		},
	})

	root, err := IssueRoot(IssueRootOpts{
		JWTID:              "organic-root",
		Issuer:             "https://issuer.example",
		Now:                now,
		ExpiresAt:          now.Add(50 * time.Minute),
		TokenType:          AATTypeDelegation,
		MaxDelegationDepth: 2,
		HolderJWK:          publicKeyToJWK(rootHolderPublic),
		Authorization:      rootAuthorization,
		Signer:             anchorPrivate,
	})
	if err != nil {
		t.Fatalf("IssueRoot failed: %v", err)
	}
	child, err := DeriveChild(root, DeriveOpts{
		JWTID:              "organic-child",
		Issuer:             thumbprintIssuer(t, rootHolderPublic),
		Now:                now.Add(time.Minute),
		ExpiresAt:          now.Add(40 * time.Minute),
		TokenType:          AATTypeDelegation,
		MaxDelegationDepth: 2,
		HolderJWK:          publicKeyToJWK(childHolderPublic),
		Authorization:      childAuthorization,
		Signer:             rootHolderPrivate,
	})
	if err != nil {
		t.Fatalf("DeriveChild failed: %v", err)
	}
	leaf, err := DeriveChild(child, DeriveOpts{
		JWTID:              "organic-grandchild",
		Issuer:             thumbprintIssuer(t, childHolderPublic),
		Now:                now.Add(2 * time.Minute),
		ExpiresAt:          now.Add(30 * time.Minute),
		TokenType:          AATTypeExecution,
		MaxDelegationDepth: 2,
		HolderJWK:          publicKeyToJWK(leafHolderPublic),
		Authorization:      leafAuthorization,
		Signer:             childHolderPrivate,
	})
	if err != nil {
		t.Fatalf("DeriveChild grandchild failed: %v", err)
	}
	args := map[string]interface{}{"path": "/tmp/a"}
	popJWT, err := BuildPoPJWT(BuildPoPOpts{
		JWTID:  "organic-pop",
		Now:    time.Now(),
		Leaf:   leaf,
		Tool:   "read_file",
		Args:   args,
		Signer: leafHolderPrivate,
	})
	if err != nil {
		t.Fatalf("BuildPoPJWT failed: %v", err)
	}
	result, err := VerifyChain(
		[]*Token{root, child, leaf},
		[][]byte{anchorPublic},
		"read_file",
		args,
		popJWT,
	)
	if err != nil || result.Verdict != VerdictPermit {
		t.Fatalf("organic chain = (%v, %v), want permit", result, err)
	}

	unknownLeafAuthorization := simpleAuthorization(ToolMap{
		"read_file": {"path": &Constraint{ConstraintType: "critical-unrecognized"}},
	})
	_, err = DeriveChild(child, DeriveOpts{
		JWTID:              "organic-unknown-grandchild",
		Issuer:             thumbprintIssuer(t, childHolderPublic),
		Now:                now.Add(2 * time.Minute),
		ExpiresAt:          now.Add(30 * time.Minute),
		TokenType:          AATTypeExecution,
		MaxDelegationDepth: 2,
		HolderJWK:          publicKeyToJWK(leafHolderPublic),
		Authorization:      unknownLeafAuthorization,
		Signer:             childHolderPrivate,
	})
	if !errors.Is(err, ErrDenyStep4Q4ConstraintSubsume) && !errors.Is(err, ErrUnknownConstraintType) {
		t.Fatalf("unknown constraint derivation error = %v, want fail-closed constraint denial", err)
	}
}

func TestDraft00VerifierAcceptsValidOlderIATAndRejectsPrivateHolderJWK(t *testing.T) {
	publicKey, privateKey := newKeyPair()
	now := time.Now()
	root, err := IssueRoot(IssueRootOpts{
		JWTID:              "older-root",
		Issuer:             "https://issuer.example",
		Now:                now.Add(-10 * time.Minute),
		ExpiresAt:          now.Add(30 * time.Minute),
		TokenType:          AATTypeExecution,
		MaxDelegationDepth: 0,
		HolderJWK:          publicKeyToJWK(publicKey),
		Authorization:      simpleAuthorization(wildcardToolMap("read_file")),
		Signer:             privateKey,
	})
	if err != nil {
		t.Fatalf("IssueRoot failed: %v", err)
	}
	popJWT, err := BuildPoPJWT(BuildPoPOpts{
		JWTID: "older-pop", Now: now, Leaf: root, Tool: "read_file",
		Args: map[string]interface{}{}, Signer: privateKey,
	})
	if err != nil {
		t.Fatalf("BuildPoPJWT failed: %v", err)
	}
	if _, err := VerifyChain(
		[]*Token{root}, [][]byte{publicKey}, "read_file", map[string]interface{}{}, popJWT,
	); err != nil {
		t.Fatalf("valid older token rejected by one-sided iat check: %v", err)
	}

	_, err = IssueRoot(IssueRootOpts{
		JWTID: "private-jwk", Issuer: "https://issuer.example", Now: now,
		ExpiresAt: now.Add(time.Hour), TokenType: AATTypeExecution,
		MaxDelegationDepth: 0, HolderJWK: privateKeyToJWK(privateKey),
		Authorization: simpleAuthorization(wildcardToolMap("read_file")), Signer: privateKey,
	})
	if err == nil {
		t.Fatal("IssueRoot accepted private holder JWK material")
	}
}

func TestAATRevisionLedgerMatchesImplementationContract(t *testing.T) {
	ledgerPath := "../../../docs/specs/aat-draft-00-to-01-change-ledger.json"
	payload, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("reading AAT revision ledger: %v", err)
	}
	var ledger struct {
		SchemaVersion string `json:"schema_version"`
		Sources       struct {
			Draft00 struct {
				Name   string `json:"name"`
				SHA256 string `json:"sha256"`
			} `json:"draft_00"`
			Draft01 struct {
				Name   string `json:"name"`
				SHA256 string `json:"sha256"`
			} `json:"draft_01"`
		} `json:"sources"`
		Decision struct {
			SelectedRevision   string `json:"selected_revision"`
			AdditionalRevision string `json:"additional_revision"`
			AdditionalProfile  string `json:"additional_profile"`
			ReviewDeadline     string `json:"review_deadline"`
			FollowUpIssue      string `json:"follow_up_issue"`
		} `json:"decision"`
		RequiredCategories []string `json:"required_categories"`
		Changes            []struct {
			Category string `json:"category"`
		} `json:"changes"`
	}
	if err := json.Unmarshal(payload, &ledger); err != nil {
		t.Fatalf("parsing AAT revision ledger: %v", err)
	}
	if ledger.SchemaVersion != "ardur.aat_revision_change_ledger.v0.1" {
		t.Fatalf("ledger schema = %q", ledger.SchemaVersion)
	}
	if ledger.Decision.SelectedRevision != SupportedDraftRevision ||
		ledger.Sources.Draft00.Name != SupportedDraftRevision {
		t.Fatalf("ledger selected revision does not match %q", SupportedDraftRevision)
	}
	if ledger.Sources.Draft01.Name != UnsupportedDraftRevision {
		t.Fatalf("ledger unsupported revision = %q, want %q", ledger.Sources.Draft01.Name, UnsupportedDraftRevision)
	}
	if ledger.Decision.AdditionalRevision != Draft01Revision ||
		ledger.Decision.AdditionalProfile != DGProfileV02 {
		t.Fatalf("ledger additional profile = %q/%q", ledger.Decision.AdditionalRevision, ledger.Decision.AdditionalProfile)
	}
	if ledger.Decision.FollowUpIssue != "https://github.com/ArdurAI/ardur-evidence/issues/246" {
		t.Fatalf("ledger follow-up issue = %q", ledger.Decision.FollowUpIssue)
	}
	if ledger.Sources.Draft00.SHA256 != "e822cc94f6b83ba81d6530f98f54617b3a9e5c7a46463bbfbdf67cb181431f1e" ||
		ledger.Sources.Draft01.SHA256 != "4e5fdd2f42cd3ff4570b711a0be5ff710236618e1f6926ef34030f82c3d04df5" {
		t.Fatal("ledger source hashes do not match the reviewed Datatracker artifacts")
	}
	deadline, err := time.Parse(time.DateOnly, ledger.Decision.ReviewDeadline)
	if err != nil || !deadline.After(time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("ledger review deadline = %q, want a valid future date", ledger.Decision.ReviewDeadline)
	}
	covered := make(map[string]bool, len(ledger.Changes))
	for _, change := range ledger.Changes {
		covered[change.Category] = true
	}
	for _, required := range ledger.RequiredCategories {
		if !covered[required] {
			t.Errorf("ledger required category %q has no change entry", required)
		}
	}
}

func TestRangeSubsumptionTightensEqualBoundInclusivity(t *testing.T) {
	bound := 10.0
	inclusive := true
	exclusive := false

	parentInclusive := &Constraint{
		ConstraintType: ConstraintTypeRange,
		Min:            &bound,
		Max:            &bound,
		MinInclusive:   &inclusive,
		MaxInclusive:   &inclusive,
	}
	childExclusive := &Constraint{
		ConstraintType: ConstraintTypeRange,
		Min:            &bound,
		Max:            &bound,
		MinInclusive:   &exclusive,
		MaxInclusive:   &exclusive,
	}
	if ok, err := SubsumesRange(parentInclusive, childExclusive); err != nil || !ok {
		t.Fatalf("inclusive parent to exclusive child = (%v, %v), want true", ok, err)
	}
	if ok, err := SubsumesRange(childExclusive, parentInclusive); err != nil || ok {
		t.Fatalf("exclusive parent to inclusive child = (%v, %v), want false", ok, err)
	}
}

func TestMalformedPatternSubsumptionFailsClosedWithoutPanic(t *testing.T) {
	parent := &Constraint{ConstraintType: ConstraintTypePattern, Value: 42}
	child := &Constraint{ConstraintType: ConstraintTypePattern, Value: "/tmp/*"}
	if ok, err := SubsumesPattern(parent, child); err != nil || ok {
		t.Fatalf("malformed pattern subsumption = (%v, %v), want false, nil", ok, err)
	}
}

func TestAllSubsumptionUsesDistinctClausesAndFindsAlternateMatching(t *testing.T) {
	parent := &Constraint{ConstraintType: ConstraintTypeAll, Children: []*Constraint{
		{ConstraintType: ConstraintTypeOneOf, Values: []interface{}{"a", "b"}},
		{ConstraintType: ConstraintTypeOneOf, Values: []interface{}{"a"}},
	}}
	oneChild := &Constraint{ConstraintType: ConstraintTypeAll, Children: []*Constraint{
		{ConstraintType: ConstraintTypeOneOf, Values: []interface{}{"a"}},
	}}
	if ok, err := SubsumesAll(parent, oneChild); err != nil || ok {
		t.Fatalf("one derived clause reused twice = (%v, %v), want false", ok, err)
	}
	twoChildren := &Constraint{ConstraintType: ConstraintTypeAll, Children: []*Constraint{
		{ConstraintType: ConstraintTypeOneOf, Values: []interface{}{"a"}},
		{ConstraintType: ConstraintTypeOneOf, Values: []interface{}{"b"}},
	}}
	if ok, err := SubsumesAll(parent, twoChildren); err != nil || !ok {
		t.Fatalf("alternate one-to-one assignment = (%v, %v), want true", ok, err)
	}
}

func TestMalformedConstraintWireAndFractionalDepthFailClosed(t *testing.T) {
	anchorPublic, anchorPrivate := newKeyPair()
	holderPublic, _ := newKeyPair()
	now := time.Now()
	baseClaims := map[string]interface{}{
		"jti":           "malformed-root",
		"iss":           "https://issuer.example",
		"iat":           now.Unix(),
		"exp":           now.Add(time.Hour).Unix(),
		"aat_type":      "execution",
		"del_depth":     0,
		"del_max_depth": 0,
		"cnf":           map[string]interface{}{"jwk": publicKeyToJWK(holderPublic)},
	}

	malformedClaims := cloneTestClaims(t, baseClaims)
	malformedClaims["authorization_details"] = []interface{}{
		map[string]interface{}{
			"type":  AuthorizationDetailType,
			"tools": map[string]interface{}{"read_file": "not-an-object"},
		},
	}
	malformed := &Token{
		Compact: signTestClaims(t, malformedClaims, anchorPrivate),
		JWTID:   "malformed-root",
	}
	_, err := VerifyChain([]*Token{malformed}, [][]byte{anchorPublic}, "read_file", nil, "unused")
	if !errors.Is(err, ErrDenyStep2CInvalidPayload) && !errors.Is(err, ErrDenyStep3NRootAuthorization) {
		t.Fatalf("malformed constraint wire error = %v, want fail-closed parse or authorization denial", err)
	}

	fractionalClaims := cloneTestClaims(t, baseClaims)
	fractionalClaims["del_depth"] = 0.5
	fractionalClaims["authorization_details"] = simpleAuthorization(wildcardToolMap("read_file"))
	fractional := &Token{
		Compact: signTestClaims(t, fractionalClaims, anchorPrivate),
		JWTID:   "malformed-root",
	}
	_, err = VerifyChain([]*Token{fractional}, [][]byte{anchorPublic}, "read_file", nil, "unused")
	if !errors.Is(err, ErrDenyStep2CInvalidPayload) && !errors.Is(err, ErrDenyStep3DInvalidRootDepth) {
		t.Fatalf("fractional depth error = %v, want parse or root-depth denial", err)
	}
}

func TestAuthorizationExtractionSelectsOnlyProfiledAATEntry(t *testing.T) {
	claims := map[string]interface{}{
		"authorization_details": []interface{}{
			map[string]interface{}{
				"type":  "unrelated_authorization_detail",
				"tools": map[string]interface{}{"dangerous": map[string]interface{}{}},
			},
			map[string]interface{}{
				"type":  AuthorizationDetailType,
				"tools": map[string]interface{}{"read_file": map[string]interface{}{}},
			},
		},
	}
	if err := validateAuthorization(claims, true); err != nil {
		t.Fatalf("valid mixed authorization details rejected: %v", err)
	}
	authorization, err := extractAuthorization(claims)
	if err != nil {
		t.Fatalf("extractAuthorization failed: %v", err)
	}
	if len(authorization) != 1 || authorization[0].Type != AuthorizationDetailType {
		t.Fatalf("extracted authorization = %#v", authorization)
	}
	if _, present := authorization[0].Tools["dangerous"]; present {
		t.Fatal("non-AAT authorization detail influenced AAT tool authority")
	}
}

func TestEmptyIntermediateCapabilityIsValidBottomElement(t *testing.T) {
	parent := &Token{Authorization: simpleAuthorization(wildcardToolMap("read_file"))}
	emptyChild := &Token{}
	if err := verifyCapabilityMonotonicity(parent, emptyChild); err != nil {
		t.Fatalf("empty child capability rejected: %v", err)
	}
	if err := verifyCapabilityMonotonicity(emptyChild, parent); !errors.Is(err, ErrDenyStep4Q1ToolExpansion) {
		t.Fatalf("tool added after empty parent error = %v, want expansion denial", err)
	}
}

func TestEmptyToolConstraintMapAuthorizesArbitraryArguments(t *testing.T) {
	leaf := &Token{
		TokenType:     AATTypeExecution,
		Authorization: simpleAuthorization(wildcardToolMap("read_file")),
	}
	args := map[string]interface{}{
		"path":       "/data/report.pdf",
		"audit_mode": true,
	}
	if err := verifyLeafInvocation(leaf, "read_file", args); err != nil {
		t.Fatalf("empty tool constraint map rejected unrestricted arguments: %v", err)
	}

	constrainedLeaf := &Token{
		TokenType: AATTypeExecution,
		Authorization: simpleAuthorization(ToolMap{
			"read_file": {
				"path": {ConstraintType: ConstraintTypeWildcard},
			},
		}),
	}
	if err := verifyLeafInvocation(constrainedLeaf, "read_file", args); !errors.Is(err, ErrDenyStep6BLeafUnknownArgument) {
		t.Fatalf("non-empty tool constraint map error = %v, want unknown-argument denial", err)
	}
}

func TestEmptyParentConstraintMapMayBeNarrowedByChild(t *testing.T) {
	parent := &Token{Authorization: simpleAuthorization(wildcardToolMap("read_file"))}
	child := &Token{Authorization: simpleAuthorization(ToolMap{
		"read_file": {
			"path": {ConstraintType: ConstraintTypeExact, Value: "/data/report.pdf"},
		},
	})}
	if err := verifyCapabilityMonotonicity(parent, child); err != nil {
		t.Fatalf("child constraints below unrestricted parent rejected: %v", err)
	}
	if err := verifyCapabilityMonotonicity(child, parent); !errors.Is(err, ErrDenyStep4Q2ArgumentShape) {
		t.Fatalf("constraint removal below non-empty parent error = %v, want shape denial", err)
	}
}

func TestDuplicateToolIdentifierWireIsRejected(t *testing.T) {
	anchorPublic, anchorPrivate := newKeyPair()
	holderPublic, _ := newKeyPair()
	now := time.Now()
	claims := map[string]interface{}{
		"jti":                   "duplicate-tool-root",
		"iss":                   "https://issuer.example",
		"iat":                   now.Unix(),
		"exp":                   now.Add(time.Hour).Unix(),
		"aat_type":              "execution",
		"del_depth":             0,
		"del_max_depth":         0,
		"cnf":                   map[string]interface{}{"jwk": publicKeyToJWK(holderPublic)},
		"authorization_details": simpleAuthorization(wildcardToolMap("read_file")),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshaling duplicate-tool fixture: %v", err)
	}
	payload = bytes.Replace(
		payload,
		[]byte(`"read_file":{}`),
		[]byte(`"read_file":{},"read_file":{}`),
		1,
	)
	if bytes.Count(payload, []byte(`"read_file"`)) != 2 {
		t.Fatalf("duplicate-tool fixture was not constructed: %s", payload)
	}
	token := &Token{Compact: signTestPayload(t, payload, anchorPrivate)}
	_, err = VerifyChain([]*Token{token}, [][]byte{anchorPublic}, "read_file", nil, "unused")
	if !errors.Is(err, ErrDenyStep2CInvalidPayload) {
		t.Fatalf("duplicate tool wire error = %v, want invalid-payload denial", err)
	}
}

func TestRegexCacheIsSafeForConcurrentVerification(t *testing.T) {
	const workers = 64
	start := make(chan struct{})
	errorsByWorker := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		worker := worker
		go func() {
			<-start
			constraint := &Constraint{
				ConstraintType: ConstraintTypeRegex,
				Pattern:        fmt.Sprintf(`^worker-%d-[0-9]+$`, worker),
			}
			errorsByWorker <- CheckRegex(fmt.Sprintf("worker-%d-42", worker), constraint)
		}()
	}
	close(start)
	for worker := 0; worker < workers; worker++ {
		if err := <-errorsByWorker; err != nil {
			t.Fatalf("concurrent regex verification failed: %v", err)
		}
	}
}

func TestDeriveChildRejectsWrongSignerBeforeMinting(t *testing.T) {
	_, anchorPrivate := newKeyPair()
	parentHolderPublic, parentHolderPrivate := newKeyPair()
	childHolderPublic, _ := newKeyPair()
	_, unrelatedPrivate := newKeyPair()
	now := time.Now()
	parent, err := IssueRoot(IssueRootOpts{
		JWTID: "wrong-signer-root", Issuer: "https://issuer.example", Now: now,
		ExpiresAt: now.Add(time.Hour), TokenType: AATTypeDelegation,
		MaxDelegationDepth: 1, HolderJWK: publicKeyToJWK(parentHolderPublic),
		Authorization: simpleAuthorization(wildcardToolMap("read_file")), Signer: anchorPrivate,
	})
	if err != nil {
		t.Fatalf("IssueRoot failed: %v", err)
	}
	opts := DeriveOpts{
		JWTID: "wrong-signer-child", Issuer: thumbprintIssuer(t, parentHolderPublic),
		Now: now.Add(time.Second), ExpiresAt: now.Add(30 * time.Minute),
		TokenType: AATTypeExecution, MaxDelegationDepth: 1,
		HolderJWK:     publicKeyToJWK(childHolderPublic),
		Authorization: simpleAuthorization(wildcardToolMap("read_file")),
		Signer:        unrelatedPrivate,
	}
	if _, err := DeriveChild(parent, opts); err == nil || !strings.Contains(err.Error(), "signer does not match") {
		t.Fatalf("wrong signer derivation error = %v", err)
	}
	opts.Signer = parentHolderPrivate
	opts.HolderJWK = publicKeyToJWK(parentHolderPublic)
	if _, err := DeriveChild(parent, opts); !errors.Is(err, ErrDenyStep4STypeTransitionKeyReuse) {
		t.Fatalf("type-transition holder-key reuse error = %v", err)
	}
	opts.HolderJWK = publicKeyToJWK(childHolderPublic)
	if _, err := DeriveChild(parent, opts); err != nil {
		t.Fatalf("matching signer derivation failed: %v", err)
	}
}

func cloneTestClaims(t *testing.T, claims map[string]interface{}) map[string]interface{} {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshaling claims clone: %v", err)
	}
	var cloned map[string]interface{}
	if err := json.Unmarshal(payload, &cloned); err != nil {
		t.Fatalf("unmarshaling claims clone: %v", err)
	}
	return cloned
}
