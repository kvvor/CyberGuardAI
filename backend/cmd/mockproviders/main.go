// Command mockproviders serves local stand-ins for the OpenAI and VirusTotal
// APIs so the complete application can be exercised without real credentials,
// network access or provider charges. Development and testing only: the
// "assessment" is a fixed rule set, not a model.
//
//	go run ./cmd/mockproviders            (listens on 127.0.0.1:18090)
//
// Start the backend with
//
//	OPENAI_BASE_URL=http://127.0.0.1:18090/openai/v1
//	VIRUSTOTAL_BASE_URL=http://127.0.0.1:18090/virustotal/api/v3
//
// and use the keys printed at startup in Settings.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"cyberguard.local/backend/internal/mockproviders"
)

func main() {
	address := os.Getenv("MOCK_PROVIDERS_ADDRESS")
	if address == "" {
		address = "127.0.0.1:18090"
	}
	mux := http.NewServeMux()
	mux.Handle("/openai/v1/", http.StripPrefix("/openai/v1", &mockproviders.OpenAI{}))
	mux.Handle("/virustotal/api/v3/", http.StripPrefix("/virustotal/api/v3", &mockproviders.VirusTotal{}))
	fmt.Println("Mock providers on http://" + address + " (test doubles, not real services)")
	fmt.Println("  OPENAI_BASE_URL=http://" + address + "/openai/v1")
	fmt.Println("  VIRUSTOTAL_BASE_URL=http://" + address + "/virustotal/api/v3")
	fmt.Println("Keys: " + mockproviders.KeyValid + " (works), " + mockproviders.KeyInvalid + ", " + mockproviders.KeyQuota + ", " + mockproviders.KeyRateLimited + ", " + mockproviders.KeyMalformed + ", " + mockproviders.KeyOverclaiming)
	fmt.Println("Models: mock-assessment-large, mock-assessment-small")
	if dir := os.Getenv("MOCK_FIXTURE_DIR"); dir != "" {
		// A harmless text file whose hash the VirusTotal mock reports as detected.
		path := filepath.Join(dir, "mock-detected-attachment.bin")
		if err := os.WriteFile(path, mockproviders.MaliciousFixture, 0600); err == nil {
			fmt.Println("Wrote harmless fixture with a 'detected' hash: " + path)
		}
	}
	server := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}
