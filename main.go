package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	client, err := newInfraiClient()
	if err != nil {
		log.Fatal(err)
	}
	secret := os.Getenv("WEBHOOK_SECRET")
	if secret == "" {
		log.Fatal("WEBHOOK_SECRET is required")
	}
	ledger := newDomainLedger()
	http.HandleFunc("/onboard", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method must be POST", http.StatusMethodNotAllowed)
			return
		}
		var input onboardingInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.TenantID == "" || input.Domain == "" || input.Origin == "" || input.CallbackURL == "" {
			http.Error(w, "tenant_id, domain, origin, and callback_url are required", http.StatusBadRequest)
			return
		}
		result, err := client.onboard(r.Context(), input, secret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ledger.record(result)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
	http.HandleFunc("/verification-finished", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method must be POST", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()
		body, err := io.ReadAll(r.Body)
		if err != nil || !verificationFinished(secret, body, r.Header.Get("X-Infrai-Signature")) {
			http.Error(w, "signature rejected", http.StatusUnauthorized)
			return
		}
		var event struct {
			Domain string `json:"domain"`
		}
		if err := json.Unmarshal(body, &event); err != nil || !ledger.finish(event.Domain) {
			http.Error(w, "domain event cannot advance a tenant", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
