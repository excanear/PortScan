package cmd

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		in  string
		out []int
	}{
		{"80,443", []int{80, 443}},
		{"1-3,80", []int{1, 2, 3, 80}},
		{"", nil},
		{"  22 ,  8080-8082 ", []int{22, 8080, 8081, 8082}},
	}

	for _, tc := range tests {
		got, err := parsePorts(tc.in)
		if err != nil {
			t.Fatalf("parsePorts(%q) returned error: %v", tc.in, err)
		}
		if !reflect.DeepEqual(got, tc.out) {
			t.Fatalf("parsePorts(%q) = %v, want %v", tc.in, got, tc.out)
		}
	}
}
