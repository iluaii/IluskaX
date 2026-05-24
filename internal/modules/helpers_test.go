package modules

import (
	"reflect"
	"testing"
)

func TestParsePhaseList(t *testing.T) {
	got := ParsePhaseList(" 4,7, 4,,10 ")
	want := []string{"4", "7", "10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParsePhaseList() = %v, want %v", got, want)
	}
}

func TestBuildPentestSkipPhasesOnly(t *testing.T) {
	got := BuildPentestSkipPhases("", "4,7")
	want := []string{"1", "2", "3", "5", "6", "8", "9", "10", "11", "12"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BuildPentestSkipPhases() = %v, want %v", got, want)
	}
}

func TestBuildPentestSkipPhasesOnlyWithSkip(t *testing.T) {
	got := BuildPentestSkipPhases("7,12", "4,7")
	want := []string{"1", "2", "3", "5", "6", "8", "9", "10", "11", "12", "7"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BuildPentestSkipPhases() = %v, want %v", got, want)
	}
}
