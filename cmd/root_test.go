package cmd

import (
	"strings"
	"testing"
	"time"
)

type textSampleNested struct {
	Value int `json:"value"`
}

type textSample struct {
	Name   string           `json:"name"`
	Tags   []string         `json:"tags"`
	Raw    string           `json:"raw"`
	Nested textSampleNested `json:"nested"`
}

func TestRenderTextReportFieldPerLine(t *testing.T) {
	report := outputReport{
		Target:      "https://example.com",
		GeneratedAt: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC),
		Results: []taskResult{
			{
				Task: "sample",
				Result: textSample{
					Name:   "value",
					Tags:   []string{"alpha", "beta"},
					Raw:    "line one\nline two\n",
					Nested: textSampleNested{Value: 42},
				},
			},
			{Task: "broken", Error: "boom"},
		},
	}

	text, err := renderTextReport(report)
	if err != nil {
		t.Fatalf("renderTextReport returned unexpected error: %v", err)
	}

	want := strings.Join([]string{
		"target: https://example.com",
		"generated_at: 2026-10-20T12:00:00Z",
		"tasks: 2",
		"",
		"task: sample",
		"name: value",
		"nested:",
		"  value: 42",
		"raw:",
		"  line one",
		"  line two",
		"tags:",
		"  - alpha",
		"  - beta",
		"",
		"task: broken",
		"error: boom",
		"",
	}, "\n")

	if text != want {
		t.Errorf("renderTextReport output mismatch\ngot:\n%s\nwant:\n%s", text, want)
	}
}

func TestRenderTextReportMarshalError(t *testing.T) {
	report := outputReport{
		Target:      "https://example.com",
		GeneratedAt: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC),
		Results:     []taskResult{{Task: "broken", Result: make(chan int)}},
	}

	if _, err := renderTextReport(report); err == nil {
		t.Fatal("renderTextReport returned nil error for unsupported result type")
	}
}
