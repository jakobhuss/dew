package main

import "testing"
import "reflect"

func TestGenLevels(t *testing.T) {
	ans := GenLevels("a.b.c.d")
	expected := []string{"a.b.c.d", "b.c.d", "c.d", "d"}

	if !reflect.DeepEqual(ans, expected) {
		t.Errorf("Expected: %s actual: %s", expected, ans)
	}

	ans = GenLevels("  a.b.c.d.")
	expected = []string{"a.b.c.d", "b.c.d", "c.d", "d"}

	if !reflect.DeepEqual(ans, expected) {
		t.Errorf("Expected: %s actual: %s", expected, ans)
	}
}

func TestRandString(t *testing.T) {
	n := 7
	s := RandString(n)

	if len(s) != n {
		t.Errorf("Expected: %d actual %d", n, len(s))
	}
}
