package scanner

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestParseOSReleaseMinimizesFields(t *testing.T) {
	t.Parallel()
	content := []byte("NAME=Ubuntu\nID=ubuntu\nVERSION_ID=\"24.04\"\nHOME_URL=https://ubuntu.com\n")
	got := parseOSRelease(content)
	want := map[string]string{"NAME": "Ubuntu", "ID": "ubuntu", "VERSION_ID": "24.04"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseOSRelease() = %#v, want %#v", got, want)
	}
}

func TestParseListeningPorts(t *testing.T) {
	t.Parallel()
	content := []byte("  sl  local_address rem_address st\n   0: 00000000:0016 00000000:0000 0A\n   1: 0100007F:1F90 00000000:0000 0A\n   2: 0100007F:0016 00000000:0000 01\n")
	got := parseListeningPorts(content)
	want := []int{22, 8080}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseListeningPorts() = %#v, want %#v", got, want)
	}
}

func TestScanProducesReadOnlyMinimalEvent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	event, err := (Scanner{Now: func() time.Time { return now }}).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if event.ID == "" || event.Kind != "host.inventory" || !event.OccurredAt.Equal(now) {
		t.Fatalf("Scan() = %#v", event)
	}
	if event.Evidence["read_only"] != true {
		t.Fatalf("scan evidence = %#v", event.Evidence)
	}
}
