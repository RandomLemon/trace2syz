package proggen

import (
	"fmt"
	"slices"

	"github.com/google/syzkaller/prog"
)

// SplitProg cuts p into chunks of at most maxCalls calls so that each chunk is a
// valid standalone program. A chunk that consumes a resource repeats the calls
// that produce it (transitively) at the front: an ioctl run on a descriptor
// drags its syz_open_dev$*-/dup$*-producers into the same chunk, which is why
// lengths are counted over the closed set. syz-manager rejects and deletes
// corpus programs longer than prog.MaxCalls (pkg/manager/seeds.go), so whole-
// trace programs have to be segmented before they can serve as seeds.
func SplitProg(p *prog.Prog, maxCalls int) ([]*prog.Prog, error) {
	if len(p.Calls) <= maxCalls {
		return []*prog.Prog{p}, nil
	}
	if maxCalls <= 0 {
		return nil, fmt.Errorf("split: bad call limit %d", maxCalls)
	}
	n := len(p.Calls)
	// owner maps every argument to the index of the call that contains it.
	owner := make(map[prog.Arg]int, 8*n)
	for i, c := range p.Calls {
		idx := i
		prog.ForeachArg(c, func(a prog.Arg, _ *prog.ArgCtx) { owner[a] = idx })
	}
	var badRef error
	// producers[i] lists the calls whose results call i consumes.
	producers := make([][]int, n)
	for i, c := range p.Calls {
		var ps []int
		seen := make(map[int]bool)
		idx := i
		prog.ForeachArg(c, func(a prog.Arg, _ *prog.ArgCtx) {
			r, ok := a.(*prog.ResultArg)
			if !ok || r.Res == nil {
				return
			}
			j, ok := owner[r.Res]
			if !ok {
				badRef = fmt.Errorf("split: call #%d references an argument outside the program", idx)
				return
			}
			if j >= idx {
				badRef = fmt.Errorf("split: call #%d references call #%d that does not precede it", idx, j)
				return
			}
			if !seen[j] {
				seen[j] = true
				ps = append(ps, j)
			}
		})
		if badRef != nil {
			return nil, badRef
		}
		slices.Sort(ps)
		producers[i] = ps
	}
	// closure[i] is the set of calls that must precede call i (i included).
	closure := make([]map[int]bool, n)
	var close func(int) map[int]bool
	close = func(i int) map[int]bool {
		if closure[i] != nil {
			return closure[i]
		}
		m := map[int]bool{i: true}
		closure[i] = m
		for _, j := range producers[i] {
			for k := range close(j) {
				m[k] = true
			}
		}
		return m
	}
	var chunks []map[int]bool
	cur := map[int]bool{}
	for i := range n {
		add := close(i)
		if len(add) > maxCalls {
			return nil, fmt.Errorf("split: call #%d needs %d calls, limit is %d", i, len(add), maxCalls)
		}
		if len(cur) > 0 {
			total := len(cur)
			for k := range add {
				if !cur[k] {
					total++
				}
			}
			if total > maxCalls {
				chunks = append(chunks, cur)
				cur = map[int]bool{}
			}
		}
		for k := range add {
			cur[k] = true
		}
	}
	if len(cur) > 0 {
		chunks = append(chunks, cur)
	}
	progs := make([]*prog.Prog, 0, len(chunks))
	for ci, set := range chunks {
		// RemoveCall also rewires the uses bookkeeping: arguments that refer to
		// dropped calls are reset to their default values. The closure above
		// guarantees that no call we keep refers to a dropped producer, so the
		// segmentation does not weaken references.
		cp := p.Clone()
		for i := len(cp.Calls) - 1; i >= 0; i-- {
			if !set[i] {
				cp.RemoveCall(i)
			}
		}
		val, err := ValidateProg(cp)
		if err != nil {
			return nil, fmt.Errorf("split: chunk %d does not validate: %w", ci, err)
		}
		progs = append(progs, val)
	}
	return progs, nil
}
