package demo

import "testing"

func TestSamples(t *testing.T) {
	for _, s := range Samples() {
		r, e := Analyze(s.ID)
		if e != nil || r.AIStatus != "predefined_demo" {
			t.Fatal(s.ID, e)
		}
		if s.ID == "legitimate" && r.Verdict != "legitimate" {
			t.Fatal("legitimate")
		}
		if s.ID == "ambiguous" && r.Verdict != "inconclusive" {
			t.Fatal("ambiguous")
		}
	}
}
