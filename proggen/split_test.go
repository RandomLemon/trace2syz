package proggen

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
)

// argOwners maps every argument of every call of p back to its owning call.
func argOwners(p *prog.Prog) map[prog.Arg]*prog.Call {
	owners := make(map[prog.Arg]*prog.Call)
	for _, c := range p.Calls {
		call := c
		prog.ForeachArg(c, func(a prog.Arg, _ *prog.ArgCtx) { owners[a] = call })
	}
	return owners
}

func bufferBytes(a prog.Arg) []byte {
	if ptr, ok := a.(*prog.PointerArg); ok {
		a = ptr.Res
	}
	if data, ok := a.(*prog.DataArg); ok {
		return data.Data()
	}
	return nil
}

func TestSplitKeepsEveryCallAndProducer(t *testing.T) {
	var trace strings.Builder
	trace.WriteString(`open("file", O_CREAT|O_RDWR) = 3` + "\n")
	for i := range 10 {
		fmt.Fprintf(&trace, "write(3, \"m%d\", 2) = 2\n", i)
	}
	p := parseSingleTrace(t, trace.String()).Prog
	const maxCalls = 3
	chunks, err := SplitProg(p, maxCalls)
	if err != nil {
		t.Fatalf("SplitProg: %v", err)
	}
	if len(chunks) < 2 {
		t.Fatalf("expected the %d-call program to be split, got %d chunk(s)", len(p.Calls), len(chunks))
	}
	target, err := prog.GetTarget(OS, Arch)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]int{}
	for ci, chunk := range chunks {
		if len(chunk.Calls) > maxCalls {
			t.Errorf("chunk %d has %d calls, limit is %d", ci, len(chunk.Calls), maxCalls)
		}
		// The chunks are what gets written into corpus.db, so they must survive
		// the same round trip the manager performs.
		decoded, err := target.Deserialize(chunk.Serialize(), prog.NonStrict)
		if err != nil {
			t.Errorf("chunk %d does not deserialize: %v", ci, err)
			continue
		}
		if len(decoded.Calls) > maxCalls {
			t.Errorf("chunk %d decodes to %d calls, limit is %d", ci, len(decoded.Calls), maxCalls)
		}
		owners := argOwners(decoded)
		for _, call := range decoded.Calls {
			if call.Meta.Name != "write" {
				continue
			}
			// The fd of every write must still reference the open() carried
			// into the same chunk, not a defaulted resource value.
			r, ok := call.Args[0].(*prog.ResultArg)
			if !ok || r.Res == nil {
				t.Errorf("chunk %d: write fd argument lost its producer: %#v", ci, call.Args[0])
				continue
			}
			if prod, ok := owners[r.Res]; !ok || prod.Meta.Name != "open" {
				t.Errorf("chunk %d: write fd does not reference an open() in the same chunk", ci)
			}
			found[strings.TrimSuffix(string(bufferBytes(call.Args[1])), "\x00")]++
		}
	}
	for i := range 10 {
		if m := fmt.Sprintf("m%d", i); found[m] != 1 {
			t.Errorf("marker %q appears %d time(s) across chunks, want exactly once", m, found[m])
		}
	}
}

func TestSplitShortProgramIsPassedThrough(t *testing.T) {
	trace := `open("file", O_CREAT|O_RDWR) = 3` + "\n" + `write(3, "x", 1) = 1`
	p := parseSingleTrace(t, trace).Prog
	chunks, err := SplitProg(p, prog.MaxCalls)
	if err != nil {
		t.Fatalf("SplitProg: %v", err)
	}
	if len(chunks) != 1 || chunks[0] != p {
		t.Fatalf("expected the %d-call program to be returned unchanged, got %d chunk(s)", len(p.Calls), len(chunks))
	}
}

func TestSplitErrorsWhenProducerClosureExceedsLimit(t *testing.T) {
	trace := `open("file", O_CREAT|O_RDWR) = 3` + "\n" + `write(3, "x", 1) = 1`
	p := parseSingleTrace(t, trace).Prog
	// A write needs the open that produces its fd plus itself: 2 calls.
	if _, err := SplitProg(p, 1); err == nil {
		t.Fatal("expected an error when a call needs more than maxCalls calls")
	}
}
