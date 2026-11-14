package passwords

import "testing"

func TestPasswords(t *testing.T) {
	for _, p := range []string{"", "short", "123456789012", "aaaaaaaaaaaa"} {
		if Validate(p) == nil {
			t.Errorf("accepted weak password %q", p)
		}
	}
	p := "Қауіпсіз ұзақ құпия сөз"
	if e := Validate(p); e != nil {
		t.Fatal(e)
	}
	h, e := Hash(p)
	if e != nil || !Verify(h, p) || Verify(h, "wrong") {
		t.Fatal("hash verification")
	}
	h2, _ := Hash(p)
	if h == h2 {
		t.Fatal("salt reused")
	}
	if Verify("$argon2id$v=19$m=999999999,t=2,p=1$x$x", p) {
		t.Fatal("unbounded parameters accepted")
	}
	if Token() == Token() {
		t.Fatal("token collision")
	}
}
