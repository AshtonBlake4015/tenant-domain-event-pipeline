package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestVerificationFinishedAcceptsOnlyTheRegisteredSecret(t *testing.T) {
	body := []byte(`{"domain":"acme.example","state":"verified"}`)
	mac := hmac.New(sha256.New, []byte("pipeline-secret"))
	mac.Write(body)
	signature := hex.EncodeToString(mac.Sum(nil))
	if !verificationFinished("pipeline-secret", body, signature) {
		t.Fatal("verified domain event should advance the tenant state")
	}
	if verificationFinished("another-secret", body, signature) {
		t.Fatal("event signed with a different secret must not advance the tenant state")
	}
}

func TestLedgerMovesOnlyWaitingTenantToVerified(t *testing.T) {
	ledger := newDomainLedger()
	ledger.record(onboardingResult{TenantID: "tenant-42", Domain: "acme.example", State: "awaiting_verification"})
	if !ledger.finish("acme.example") {
		t.Fatal("verified domain event should advance the tenant state")
	}
	if ledger.finish("acme.example") {
		t.Fatal("a completed tenant must not advance twice")
	}
}
