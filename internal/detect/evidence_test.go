package detect

import (
	"math"
	"testing"
)

func TestEvidenceScore(t *testing.T) {
	tests := []struct {
		name string
		l    float64
		want float64
	}{
		{"L=3.0", 3.0, 0.9526},
		{"L=2.2", 2.2, 0.9002},
		{"L=0", 0, 0.5},
		{"L=-0.85", -0.85, 0.2994},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEvidence(tt.l)
			got := e.score()
			if math.Abs(got-tt.want) > 1e-4 {
				t.Errorf("score() = %.6f, want %.4f (±1e-4)", got, tt.want)
			}
		})
	}
}

func TestEvidenceString(t *testing.T) {
	e := newEvidence(-2.5)
	e.add("first:t3", 2.0)
	e.add("pair", 1.5)
	want := "prior-2.5 first:t3+2.0 pair+1.5"
	if got := e.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestEvidenceMatch(t *testing.T) {
	t.Run("below minScore", func(t *testing.T) {
		e := newEvidence(-1.0)
		if _, ok := e.match(TypeEmail, 0, 5, "value/email", "email"); ok {
			t.Error("match() ok = true for score 0.27, want false")
		}
	})
	t.Run("at or above minScore", func(t *testing.T) {
		e := newEvidence(-0.8)
		m, ok := e.match(TypeEmail, 3, 8, "value/email", "email")
		if !ok {
			t.Fatal("match() ok = false for score 0.31, want true")
		}
		if math.Abs(m.Score-0.31) > 1e-2 {
			t.Errorf("Score = %.4f, want ≈ 0.31", m.Score)
		}
		if m.Evidence != "prior-0.8" {
			t.Errorf("Evidence = %q, want %q", m.Evidence, "prior-0.8")
		}
		if m.Type != TypeEmail || m.Start != 3 || m.End != 8 || m.Detector != "value/email" || m.Rule != "email" {
			t.Errorf("match fields = %+v", m)
		}
		if m.Field != "" {
			t.Errorf("Field = %q, want empty", m.Field)
		}
	})
}

func TestEntityTypesNew(t *testing.T) {
	if TypeMAC != "MAC_ADDRESS" {
		t.Errorf("TypeMAC = %q, want MAC_ADDRESS", TypeMAC)
	}
	if TypeVIN != "VIN" {
		t.Errorf("TypeVIN = %q, want VIN", TypeVIN)
	}
}
