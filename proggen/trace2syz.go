package proggen

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"

	"github.com/RandomLemon/trace2syz/parser"
	"github.com/RandomLemon/trace2syz/utils"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

type returnCache map[resourceDescription]prog.Arg

func newRCache() returnCache {
	return make(returnCache)
}

func (r *returnCache) buildKey(syzType prog.Type) string {
	switch a := syzType.(type) {
	case *prog.ResourceType:
		// Kind[0] is the root resource (fd), which every device-specific
		// resource transitively descends from; using it keeps generic and
		// specific lookups interchangeable.
		return "ResourceType-" + a.Desc.Kind[0]
	default:
		log.Fatalf("Caching non resource type")
	}
	return ""
}

// specificKey returns the cache key for the most specific resource kind, so the
// device identity of a descriptor can be recovered later (see lookupByVal).
func (r *returnCache) specificKey(syzType prog.Type) string {
	a, ok := syzType.(*prog.ResourceType)
	if !ok {
		log.Fatalf("Caching non resource type")
	}
	return "ResourceType-" + a.Desc.Kind[len(a.Desc.Kind)-1]
}

// kindOf returns the resource kind recorded in a cache key.
func kindOf(key string) string {
	return strings.TrimPrefix(key, "ResourceType-")
}

func (r *returnCache) cache(syzType prog.Type, traceType parser.IrType, arg prog.Arg) {
	log.Logf(2, "Caching resource type: %s, val: %s", r.buildKey(syzType), traceType.String())
	resDesc := resourceDescription{
		Type: r.buildKey(syzType),
		Val:  traceType.String(),
	}
	(*r)[resDesc] = arg
	if spec, ok := syzType.(*prog.ResourceType); ok && spec.Desc.Kind[0] != spec.Desc.Kind[len(spec.Desc.Kind)-1] {
		// Also record the device-specific kind so dup handling can recover it.
		(*r)[resourceDescription{Type: r.specificKey(syzType), Val: traceType.String()}] = arg
	}
}

// alias duplicates every cached resource whose fd value is oldVal under newVal.
// dup/dup2/dup3/fcntl(F_DUPFD*) make a second descriptor refer to the same file;
// without this the resource type is lost and later ioctls fall back to the generic
// (unconstrained) ioctl description.
func (r *returnCache) alias(oldVal, newVal int64) {
	oldStr := strconv.FormatInt(oldVal, 10)
	newStr := strconv.FormatInt(newVal, 10)
	for desc, arg := range *r {
		if desc.Val != oldStr {
			continue
		}
		(*r)[resourceDescription{Type: desc.Type, Val: newStr}] = arg
	}
}

// lookupByVal returns the most specific resource kind cached for an fd value.
// Device-specific kinds are preferred over the generic root (fd).
func (r *returnCache) lookupByVal(val int64) string {
	valStr := strconv.FormatInt(val, 10)
	best := ""
	for desc := range *r {
		if desc.Val != valStr {
			continue
		}
		if kind := kindOf(desc.Type); len(kind) > len(best) {
			best = kind
		}
	}
	return best
}

func (r *returnCache) get(syzType prog.Type, traceType parser.IrType) prog.Arg {
	log.Logf(2, "Fetching resource type: %s, val: %s", r.buildKey(syzType), traceType.String())
	resDesc := resourceDescription{
		Type: r.buildKey(syzType),
		Val:  traceType.String(),
	}
	if arg, ok := (*r)[resDesc]; ok {
		if arg != nil {
			log.Logf(2, "Cache hit for resource type: %s, val: %s", r.buildKey(syzType), traceType.String())
			return arg
		}
	}
	return nil
}

type resourceDescription struct {
	Type string
	Val  string
}

// Context stores metadata related to a syzkaller program
// Currently we are embedding the State object within the Context.
// We should probably merge the two objects
type Context struct {
	ReturnCache       returnCache
	Prog              *prog.Prog
	CurrentStraceCall *parser.Syscall
	CurrentSyzCall    *prog.Call
	CurrentStraceArg  parser.IrType
	Target            *prog.Target
	Tracker           *memoryTracker
	CallToCover       map[*prog.Call][]uint64
	Call2Variant      *CallVariantMap
	DependsOn         map[*prog.Call]map[*prog.Call]int
}

func newContext(target *prog.Target, variantMap *CallVariantMap) (ctx *Context) {
	ctx = &Context{}
	ctx.ReturnCache = newRCache()
	ctx.CurrentStraceCall = nil
	ctx.Tracker = newTracker()
	ctx.CurrentStraceArg = nil
	ctx.Target = target
	ctx.CallToCover = make(map[*prog.Call][]uint64)
	ctx.Call2Variant = variantMap
	ctx.DependsOn = make(map[*prog.Call]map[*prog.Call]int)
	return
}

// makeMmapCall builds the single mmap call that reserves the program's data
// region. It replaces the pre-module prog.Target.MakeMmap(addr, size) hook,
// which no longer exists; the shape follows the current
// sys/targets.MakePosixMmap so the call stays valid against the current
// syscall description (including targets with a padding argument before
// offset).
func makeMmapCall(target *prog.Target, size uint64) *prog.Call {
	meta := target.SyscallMap["mmap"]
	prot := target.ConstMap["PROT_READ"] | target.ConstMap["PROT_WRITE"]
	flags := target.ConstMap["MAP_ANONYMOUS"] | target.ConstMap["MAP_PRIVATE"] | target.ConstMap["MAP_FIXED"]
	const invalidFD = ^uint64(0)
	call := prog.MakeCall(meta, []prog.Arg{
		prog.MakeVmaPointerArg(meta.Args[0].Type, prog.DirIn, 0, size),
		prog.MakeConstArg(meta.Args[1].Type, prog.DirIn, size),
		prog.MakeConstArg(meta.Args[2].Type, prog.DirIn, prot),
		prog.MakeConstArg(meta.Args[3].Type, prog.DirIn, flags),
		prog.MakeResultArg(meta.Args[4].Type, prog.DirIn, nil, invalidFD),
	})
	i := len(call.Args)
	// Some targets have a padding argument between fd and offset.
	if len(meta.Args) > 6 {
		call.Args = append(call.Args, prog.MakeConstArg(meta.Args[i].Type, prog.DirIn, 0))
		i++
	}
	call.Args = append(call.Args, prog.MakeConstArg(meta.Args[i].Type, prog.DirIn, 0))
	return call
}

// FillOutMemory determines how much memory to allocate for arguments in a program
// And generates an mmap c to do the allocation.This mmap is prepended to prog.Calls
func (ctx *Context) FillOutMemory() error {
	err := ctx.Tracker.fillOutMemory(ctx.Prog)
	if err != nil {
		return err
	}
	totalMemory := ctx.Tracker.getTotalMemoryAllocations(ctx.Prog)
	log.Logf(2, "Total memory for program is: %d", totalMemory)
	if totalMemory == 0 {
		log.Logf(1, "Program requires no mmaps. Total memory: %d", totalMemory)
		return nil
	}
	mmapCall := makeMmapCall(ctx.Target, totalMemory)
	calls := make([]*prog.Call, 0)
	calls = append(append(calls, mmapCall), ctx.Prog.Calls...)
	ctx.Prog.Calls = calls
	return nil
}

// GenSyzProg converts a trace to a syzkaller program
func GenSyzProg(trace *parser.Trace, target *prog.Target, variantMap *CallVariantMap) *Context {
	syzProg := new(prog.Prog)
	syzProg.Target = target
	ctx := newContext(target, variantMap)
	ctx.Prog = syzProg
	var call *prog.Call
	for _, sCall := range trace.Calls {
		if sCall.Paused {
			// Probably a case where the call was killed by a signal like the following
			// 2179  wait4(2180,  <unfinished ...>
			// 2179  <... wait4 resumed> 0x7fff28981bf8, 0, NULL) = ? ERESTARTSYS
			// 2179  --- SIGUSR1 {si_signo=SIGUSR1, si_code=SI_USER, si_pid=2180, si_uid=0} ---
			continue
		}
		ctx.CurrentStraceCall = sCall

		if shouldSkip(ctx) {
			log.Logf(3, "Skipping call: %s", ctx.CurrentStraceCall.CallName)
			continue
		}
		if call = genCall(ctx); call == nil {
			continue
		}

		ctx.CallToCover[call] = sCall.Cover
		syzProg.Calls = append(syzProg.Calls, call)
	}
	return ctx
}

func genCall(ctx *Context) *prog.Call {
	log.Logf(2, "parsing call: %s", ctx.CurrentStraceCall.CallName)
	straceCall := ctx.CurrentStraceCall
	syzCallDef := ctx.Target.SyscallMap[straceCall.CallName]
	retCall := new(prog.Call)
	retCall.Meta = syzCallDef
	ctx.CurrentSyzCall = retCall

	preprocess(ctx)
	if ctx.CurrentSyzCall.Meta == nil {
		// A call like fcntl may have variants like fcntl$get_flag
		// but no generic fcntl system call in Syzkaller
		return nil
	}
	retCall.Ret = prog.MakeReturnArg(ctx.CurrentSyzCall.Meta.Ret)

	if call := parseMemoryCall(ctx); call != nil {
		return call
	}
	for i := range retCall.Meta.Args {
		var strArg parser.IrType
		if i < len(straceCall.Args) {
			strArg = straceCall.Args[i]
		}
		res := genArgs(retCall.Meta.Args[i].Type, prog.DirIn, strArg, ctx)
		retCall.Args = append(retCall.Args, res)
	}
	genResult(retCall.Meta.Ret, straceCall.Ret, ctx)
	return retCall
}

func genResult(syzType prog.Type, straceRet int64, ctx *Context) {
	if straceRet > 0 {
		if oldFd := dupSourceFd(ctx); oldFd >= 0 {
			ctx.ReturnCache.alias(oldFd, straceRet)
		}
		straceExpr := parser.NewIntsType([]int64{straceRet})
		switch syzType.(type) {
		case *prog.ResourceType:
			log.Logf(2, "Call: %s returned a resource type with val: %s",
				ctx.CurrentStraceCall.CallName, straceExpr.String())
			ctx.ReturnCache.cache(syzType, straceExpr, ctx.CurrentSyzCall.Ret)
		}
	}
}

// dupSourceFd returns the source fd when the current call duplicates a descriptor,
// or -1 for every other call.
func dupSourceFd(ctx *Context) int64 {
	switch ctx.CurrentStraceCall.CallName {
	case "dup", "dup2", "dup3":
		if len(ctx.CurrentStraceCall.Args) == 0 {
			return -1
		}
		if e, ok := ctx.CurrentStraceCall.Args[0].(parser.Expression); ok {
			return int64(e.Eval(ctx.Target))
		}
	}
	return -1
}

// pathArgIndex returns the index of the path argument for the calls whose path
// is validated by syzkaller (see prog/rand.go escapingFilename), or -1.
func pathArgIndex(callName string) int {
	switch callName {
	case "open", "stat", "stat64", "lstat", "access", "unlink", "readlink",
		"mkdir", "rmdir", "chdir", "chmod", "chown", "truncate", "execve":
		return 0
	case "symlink":
		return 1 // oldpath is arg0, newpath (validated) is arg1
	case "openat", "newfstatat", "faccessat", "unlinkat", "mkdirat", "readlinkat",
		"fchmodat", "fchownat", "utimensat":
		return 1
	}
	return -1
}

// isAbsolutePathOpen reports whether the call names a file by an absolute path.
func isAbsolutePathOpen(syscall *parser.Syscall) bool {
	idx := pathArgIndex(syscall.CallName)
	if idx < 0 || idx >= len(syscall.Args) {
		return false
	}
	buf, ok := syscall.Args[idx].(*parser.BufferType)
	if !ok {
		return false
	}
	return strings.HasPrefix(buf.Val, "/") || strings.HasPrefix(buf.Val, "..")
}

// isUnixAbsSocket reports whether the call connects/binds a unix socket to an
// absolute path, which syzkaller also rejects as a sandbox escape and which
// would make the whole program unloadable.
func isUnixAbsSocket(syscall *parser.Syscall) bool {
	switch syscall.CallName {
	case "connect", "bind":
	default:
		return false
	}
	if len(syscall.Args) < 2 {
		return false
	}
	// The sockaddr may be wrapped in a pointer, so search the whole argument.
	return hasAbsoluteBuffer(syscall.Args[1])
}

// hasAbsoluteBuffer reports whether any nested buffer of the IR node starts with '/'.
func hasAbsoluteBuffer(node parser.IrType) bool {
	switch n := node.(type) {
	case *parser.BufferType:
		return strings.HasPrefix(n.Val, "/")
	case *parser.GroupType:
		for _, e := range n.Elems {
			if hasAbsoluteBuffer(e) {
				return true
			}
		}
	case *parser.Field:
		return hasAbsoluteBuffer(n.Val)
	}
	return false
}

// isKnownDevice reports whether the path opened by an open/openat call matches a
// syz_open_dev pattern, i.e. whether the call will be rebound to a
// device-specific resource. Only open/openat qualify: for any other call an
// absolute path stays an absolute path and makes the program unloadable.
func isKnownDevice(ctx *Context, syscall *parser.Syscall) bool {
	var idx int
	switch syscall.CallName {
	case "open":
		idx = 0
	case "openat":
		idx = 1
	default:
		return false
	}
	if idx >= len(syscall.Args) {
		return false
	}
	buf, ok := syscall.Args[idx].(*parser.BufferType)
	if !ok {
		return false
	}
	path := strings.TrimRight(buf.Val, "\x00")
	for _, pat := range ctx.Call2Variant.Open {
		if matched, _ := pat.matchPath(path); matched {
			return true
		}
	}
	return false
}

func genArgs(syzType prog.Type, dir prog.Dir, traceArg parser.IrType, ctx *Context) prog.Arg {
	if traceArg == nil {
		log.Logf(3, "Parsing syzType: %s, traceArg is nil. Generating default arg...", syzType.Name())
		return genDefaultArg(syzType, dir, ctx)
	}
	ctx.CurrentStraceArg = traceArg
	log.Logf(3, "Parsing Arg of syz type: %s, ir type: %s", syzType.Name(), traceArg.Name())

	switch a := syzType.(type) {
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.CsumType:
		return genConst(a, dir, traceArg, ctx)
	case *prog.LenType:
		return genDefaultArg(syzType, dir, ctx)
	case *prog.ProcType:
		return parseProc(a, dir, traceArg, ctx)
	case *prog.ResourceType:
		return genResource(a, dir, traceArg, ctx)
	case *prog.PtrType:
		return genPtr(a, dir, traceArg, ctx)
	case *prog.BufferType:
		return genBuffer(a, dir, traceArg, ctx)
	case *prog.StructType:
		return genStruct(a, dir, traceArg, ctx)
	case *prog.ArrayType:
		return genArray(a, dir, traceArg, ctx)
	case *prog.UnionType:
		return genUnionArg(a, dir, traceArg, ctx)
	case *prog.VmaType:
		return genVma(a, dir, traceArg, ctx)
	default:
		log.Fatalf("Unsupported  Type: %v", syzType)
	}
	return nil
}

func genVma(syzType *prog.VmaType, dir prog.Dir, traceType parser.IrType, ctx *Context) prog.Arg {
	var npages uint64 = 1
	// TODO: strace doesn't give complete info, need to guess random page range
	if syzType.RangeBegin != 0 || syzType.RangeEnd != 0 {
		npages = syzType.RangeEnd
	}
	arg := prog.MakeVmaPointerArg(syzType, dir, 0, npages)
	ctx.Tracker.addAllocation(ctx.CurrentSyzCall, ctx.Target.PageSize, arg)
	return arg
}

func genArray(syzType *prog.ArrayType, dir prog.Dir, traceType parser.IrType, ctx *Context) prog.Arg {
	var args []prog.Arg
	switch a := traceType.(type) {
	case *parser.GroupType:
		if dir == prog.DirOut {
			return genDefaultArg(syzType, dir, ctx)
		}
		for i := 0; i < a.Len; i++ {
			args = append(args, genArgs(syzType.Elem, dir, a.Elems[i], ctx))
		}
	case *parser.Field:
		return genArray(syzType, dir, a.Val, ctx)
	case *parser.PointerType, parser.Expression, *parser.BufferType:
		return genDefaultArg(syzType, dir, ctx)
	default:
		log.Fatalf("Error parsing Array: %s with Wrong Type: %s", syzType.Name(), traceType.Name())
	}
	return prog.MakeGroupArg(syzType, dir, args)
}

func genStruct(syzType *prog.StructType, dir prog.Dir, traceType parser.IrType, ctx *Context) prog.Arg {
	if dir == prog.DirOut {
		return genDefaultArg(syzType, dir, ctx)
	}
	traceType = preprocessStruct(syzType, traceType, ctx)
	args := make([]prog.Arg, 0)
	switch a := traceType.(type) {
	case *parser.GroupType:
		reorderStructFields(syzType, a, ctx)
		args = append(args, evalFields(syzType.Fields, a.Elems, dir, ctx)...)
	case *parser.Field:
		return genArgs(syzType, dir, a.Val, ctx)
	case *parser.Call:
		args = append(args, parseInnerCall(syzType, dir, a, ctx))
	case parser.Expression:
		return genDefaultArg(syzType, dir, ctx)
	case *parser.BufferType:
		return genDefaultArg(syzType, dir, ctx)
	default:
		log.Fatalf("Unsupported Strace Type: %#v to Struct Type", a)
	}
	return prog.MakeGroupArg(syzType, dir, args)
}

func evalFields(syzFields []prog.Field, straceFields []parser.IrType, dir prog.Dir, ctx *Context) []prog.Arg {
	var args []prog.Arg
	j := 0
	for i := range syzFields {
		fldDir := syzFields[i].Dir(dir)
		if prog.IsPad(syzFields[i].Type) {
			args = append(args, syzFields[i].DefaultArg(fldDir))
		} else {
			if j >= len(straceFields) {
				args = append(args, genDefaultArg(syzFields[i].Type, fldDir, ctx))
			} else {
				args = append(args, genArgs(syzFields[i].Type, fldDir, straceFields[j], ctx))
			}
			j++
		}
	}
	return args
}

func genUnionArg(syzType *prog.UnionType, dir prog.Dir, straceType parser.IrType, ctx *Context) prog.Arg {
	if straceType == nil {
		log.Logf(1, "Generating union arg. StraceType is nil")
	} else {
		log.Logf(4, "Generating union arg: %s %s", syzType.TypeName, straceType.Name())
	}
	switch strType := straceType.(type) {
	case *parser.Field:
		switch strValType := strType.Val.(type) {
		case *parser.Call:
			return parseInnerCall(syzType, dir, strValType, ctx)
		default:
			return genUnionArg(syzType, dir, strType.Val, ctx)
		}
	case *parser.Call:
		return parseInnerCall(syzType, dir, strType, ctx)
	default:
		idx := identifyUnionType(syzType, ctx, syzType.TypeName)
		if idx < 0 || idx >= len(syzType.Fields) {
			return syzType.DefaultArg(dir)
		}
		innerType := syzType.Fields[idx]
		innerArg := genArgs(innerType.Type, innerType.Dir(dir), straceType, ctx)
		return prog.MakeUnionArg(syzType, dir, innerArg, idx)
	}
}

func identifyUnionType(syzType *prog.UnionType, ctx *Context, typeName string) int {
	log.Logf(4, "Identifying union arg: %s", syzType.TypeName)
	switch typeName {
	case "sockaddr_storage":
		return identifySockaddrStorage(syzType, ctx)
	case "sockaddr_nl":
		return identifySockaddrNetlinkUnion(syzType, ctx)
	case "ifr_ifru":
		return identifyIfrIfruUnion(ctx)
	case "ifconf":
		return identifyIfconfUnion(ctx)
	case "bpf_instructions":
		return 0
	case "bpf_insn":
		return 1
	}
	return 0
}

func identifySockaddrStorage(syzType *prog.UnionType, ctx *Context) int {
	field2Opt := make(map[string]int)
	for i, field := range syzType.Fields {
		field2Opt[field.Name] = i
	}
	// We currently look at the first argument of the system call
	// To determine which option of the union we select.
	call := ctx.CurrentStraceCall
	var straceArg parser.IrType
	switch call.CallName {
	// May need to handle special cases.
	case "recvfrom":
		straceArg = call.Args[4]
	default:
		if len(call.Args) >= 2 {
			straceArg = call.Args[1]
		} else {
			log.Fatalf("Unable identify union for sockaddr_storage for call: %s",
				call.CallName)
		}
	}
	switch strType := straceArg.(type) {
	case *parser.GroupType:
		for i := range strType.Elems {
			fieldStr := strType.Elems[i].String()
			if strings.Contains(fieldStr, "AF_INET6") {
				return field2Opt["in6"]
			} else if strings.Contains(fieldStr, "AF_INET") {
				return field2Opt["in"]
			} else if strings.Contains(fieldStr, "AF_UNIX") {
				return field2Opt["un"]
			} else if strings.Contains(fieldStr, "AF_NETLINK") {
				return field2Opt["nl"]
			} else {
				log.Fatalf("Unable to identify option for sockaddr storage union."+
					" Field is: %s", fieldStr)
			}
		}
	default:
		log.Fatalf("Failed to parse Sockaddr Stroage Union Type. Strace Type: %#v", strType)
	}
	return -1
}

func identifySockaddrNetlinkUnion(syzType *prog.UnionType, ctx *Context) int {
	field2Opt := make(map[string]int)
	for i, field := range syzType.Fields {
		field2Opt[field.Name] = i
	}
	switch a := ctx.CurrentStraceArg.(type) {
	case *parser.GroupType:
		if len(a.Elems) > 2 {
			switch b := a.Elems[1].(type) {
			case parser.Expression:
				pid := b.Eval(ctx.Target)
				if pid > 0 {
					// User
					return field2Opt["proc"]
				} else if pid == 0 {
					// Kernel
					return field2Opt["kern"]
				} else {
					// Unspec
					return field2Opt["unspec"]
				}
			case *parser.Field:
				curArg := ctx.CurrentStraceArg
				ctx.CurrentStraceArg = b.Val
				idx := identifySockaddrNetlinkUnion(syzType, ctx)
				ctx.CurrentStraceArg = curArg
				return idx
			default:
				log.Fatalf("Parsing netlink addr struct and expect expression for first arg: %s", a.Name())
			}
		}
	}
	return 2
}

func identifyIfrIfruUnion(ctx *Context) int {
	switch ctx.CurrentStraceArg.(type) {
	case parser.Expression:
		return 2
	case *parser.Field:
		return 2
	default:
		return 0
	}
}

func identifyIfconfUnion(ctx *Context) int {
	switch ctx.CurrentStraceArg.(type) {
	case *parser.GroupType:
		return 1
	default:
		return 0
	}
}

func genBuffer(syzType *prog.BufferType, dir prog.Dir, traceType parser.IrType, ctx *Context) prog.Arg {
	if dir == prog.DirOut {
		if !syzType.Varlen() {
			return prog.MakeOutDataArg(syzType, dir, syzType.Size())
		}
		switch a := traceType.(type) {
		case *parser.BufferType:
			return prog.MakeOutDataArg(syzType, dir, uint64(len(a.Val)))
		case *parser.Field:
			return genBuffer(syzType, dir, a.Val, ctx)
		default:
			switch syzType.Kind {
			case prog.BufferBlobRand:
				size := rand.IntN(256)
				return prog.MakeOutDataArg(syzType, dir, uint64(size))

			case prog.BufferBlobRange:
				max := rand.IntN(int(syzType.RangeEnd) - int(syzType.RangeBegin) + 1)
				size := max + int(syzType.RangeBegin)
				return prog.MakeOutDataArg(syzType, dir, uint64(size))
			default:
				panic(fmt.Sprintf("unexpected buffer type kind: %v. call %v arg %v", syzType.Kind, ctx.CurrentSyzCall, traceType))
			}
		}
	}
	var bufVal []byte
	switch a := traceType.(type) {
	case *parser.BufferType:
		bufVal = []byte(a.Val)
	case parser.Expression:
		val := a.Eval(ctx.Target)
		bArr := make([]byte, 8)
		binary.LittleEndian.PutUint64(bArr, val)
		bufVal = bArr
	case *parser.PointerType:
		val := a.Address
		bArr := make([]byte, 8)
		binary.LittleEndian.PutUint64(bArr, val)
		bufVal = bArr
	case *parser.GroupType:
		return genDefaultArg(syzType, dir, ctx)
	case *parser.Field:
		return genArgs(syzType, dir, a.Val, ctx)
	default:
		log.Fatalf("Cannot parse type %#v for Buffer Type\n", traceType)
	}
	if !syzType.Varlen() {
		size := syzType.Size()
		for uint64(len(bufVal)) < size {
			bufVal = append(bufVal, 0)
		}
		bufVal = bufVal[:size]
	}
	return prog.MakeDataArg(syzType, dir, bufVal)
}

func genPtr(syzType *prog.PtrType, dir prog.Dir, traceType parser.IrType, ctx *Context) prog.Arg {
	switch a := traceType.(type) {
	case *parser.PointerType:
		if a.IsNull() {
			return syzType.DefaultArg(dir)
		}
		if a.Res == nil {
			res := genDefaultArg(syzType.Elem, syzType.ElemDir, ctx)
			return addr(ctx, syzType, dir, res.Size(), res)
		}
		res := genArgs(syzType.Elem, syzType.ElemDir, a.Res, ctx)
		return addr(ctx, syzType, dir, res.Size(), res)

	case parser.Expression:
		// Likely have a type of the form bind(3, 0xfffffffff, [3]);
		res := genDefaultArg(syzType.Elem, syzType.ElemDir, ctx)
		return addr(ctx, syzType, dir, res.Size(), res)
	case *parser.Field:
		return genPtr(syzType, dir, a.Val, ctx)
	default:
		res := genArgs(syzType.Elem, syzType.ElemDir, a, ctx)
		return addr(ctx, syzType, dir, res.Size(), res)
	}
}

func genConst(syzType prog.Type, dir prog.Dir, traceType parser.IrType, ctx *Context) prog.Arg {
	if dir == prog.DirOut {
		return syzType.DefaultArg(dir)
	}
	switch a := traceType.(type) {
	case parser.Expression:
		switch b := a.(type) {
		case parser.Ints:
			if len(b) >= 2 {
				// May get here through select. E.g. select(2, [6, 7], ..) since Expression can
				// be Ints. However, creating fd set is hard and we let default arg through
				return genDefaultArg(syzType, dir, ctx)
			}
		}

		return prog.MakeConstArg(syzType, dir, a.Eval(ctx.Target))
	case *parser.DynamicType:
		return prog.MakeConstArg(syzType, dir, a.BeforeCall.Eval(ctx.Target))
	case *parser.GroupType:
		// Sometimes strace represents a pointer to int as [0] which gets parsed
		// as Array([0], len=1). A good example is ioctl(3, FIONBIO, [1]). We may also have an union int type that
		// is a represented as a struct in strace e.g.
		// sigev_value={sival_int=-2123636944, sival_ptr=0x7ffd816bdf30}
		// For now we choose the first option
		if a.Len == 0 {
			log.Fatalf("Parsing const type. Got array type with len 0: %#v", ctx)
		}
		return genConst(syzType, dir, a.Elems[0], ctx)

	case *parser.Field:
		// We have an argument of the form sin_port=IntType(0)
		return genArgs(syzType, dir, a.Val, ctx)
	case *parser.Call:
		// We have likely hit a call like inet_pton, htonl, etc
		return parseInnerCall(syzType, dir, a, ctx)
	case *parser.BufferType:
		// The call almost certainly an error or missing fields
		return genDefaultArg(syzType, dir, ctx)
		// E.g. ltp_bind01 two arguments are empty and
	case *parser.PointerType:
		// This can be triggered by the following:
		// 2435  connect(3, {sa_family=0x2f ,..., 16)
		return prog.MakeConstArg(syzType, dir, a.Address)
	default:
		log.Fatalf("Cannot convert Strace Type: %s to Const Type", traceType.Name())
	}
	return nil
}

func genResource(syzType *prog.ResourceType, dir prog.Dir, traceType parser.IrType, ctx *Context) prog.Arg {
	if dir == prog.DirOut {
		log.Logf(2, "Resource returned by call argument: %s", traceType.String())
		res := prog.MakeResultArg(syzType, dir, nil, syzType.Default())
		ctx.ReturnCache.cache(syzType, traceType, res)
		return res
	}
	switch a := traceType.(type) {
	case parser.Expression:
		val := a.Eval(ctx.Target)
		if arg := ctx.ReturnCache.get(syzType, traceType); arg != nil {
			res := prog.MakeResultArg(syzType, dir, arg.(*prog.ResultArg), syzType.Default())
			return res
		}
		res := prog.MakeResultArg(syzType, dir, nil, val)
		return res
	case *parser.Field:
		return genResource(syzType, dir, a.Val, ctx)
	default:
		log.Fatalf("Resource Type only supports Expression")
	}
	return nil
}

func parseProc(syzType *prog.ProcType, dir prog.Dir, traceType parser.IrType, ctx *Context) prog.Arg {
	if dir == prog.DirOut {
		return genDefaultArg(syzType, dir, ctx)
	}
	switch a := traceType.(type) {
	case parser.Expression:
		val := a.Eval(ctx.Target)
		if val >= syzType.ValuesPerProc {
			return prog.MakeConstArg(syzType, dir, syzType.ValuesPerProc-1)
		}
		return prog.MakeConstArg(syzType, dir, val)
	case *parser.Field:
		return genArgs(syzType, dir, a.Val, ctx)
	case *parser.Call:
		return parseInnerCall(syzType, dir, a, ctx)
	case *parser.BufferType:
		// Again probably an error case
		// Something like the following will trigger this
		// bind(3, {sa_family=AF_INET, sa_data="\xac"}, 3) = -1 EINVAL(Invalid argument)
		return genDefaultArg(syzType, dir, ctx)
	default:
		log.Fatalf("Unsupported Type for Proc: %#v\n", traceType)
	}
	return nil
}

func genDefaultArg(syzType prog.Type, dir prog.Dir, ctx *Context) prog.Arg {
	switch a := syzType.(type) {
	case *prog.PtrType:
		res := a.Elem.DefaultArg(a.ElemDir)
		return addr(ctx, syzType, dir, res.Size(), res)
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.LenType, *prog.ProcType,
		*prog.CsumType, *prog.BufferType, *prog.ArrayType, *prog.ResourceType, *prog.VmaType:
		return a.DefaultArg(dir)
	case *prog.StructType:
		var inner []prog.Arg
		for i := range a.Fields {
			inner = append(inner, genDefaultArg(a.Fields[i].Type, a.Fields[i].Dir(dir), ctx))
		}
		return prog.MakeGroupArg(a, dir, inner)
	case *prog.UnionType:
		return a.DefaultArg(dir)
	default:
		log.Fatalf("Unsupported Type: %#v", syzType)
	}
	return nil
}

func addr(ctx *Context, syzType prog.Type, dir prog.Dir, size uint64, data prog.Arg) prog.Arg {
	arg := prog.MakePointerArg(syzType, dir, uint64(0), data)
	ctx.Tracker.addAllocation(ctx.CurrentSyzCall, size, arg)
	return arg
}

// ValidateProg runs a generated program through the current prog.Builder, the
// only exported path to assignSizesCall + Neutralize + validation (the
// pre-module exports Prog.Validate, Target.AssignSizesCall and
// Target.SanitizeCall no longer exist). The Builder keeps the same *Call
// pointers, so the returned program has the same calls with sizes and
// neutralization applied, and Size lengths are resolved.
func ValidateProg(p *prog.Prog) (*prog.Prog, error) {
	b := prog.MakeProgGen(p.Target)
	for _, call := range p.Calls {
		if err := b.Append(call); err != nil {
			return nil, err
		}
	}
	return b.Finalize()
}

func reorderStructFields(syzType *prog.StructType, traceType *parser.GroupType, ctx *Context) {
	// Sometimes strace reports struct fields out of order compared to Syzkaller.
	// Example: 5704  bind(3, {sa_family=AF_INET6,
	//				sin6_port=htons(8888),
	//				inet_pton(AF_INET6, "::", &sin6_addr),
	//				sin6_flowinfo=htonl(2206138368),
	//				sin6_scope_id=2049825634}, 128) = 0
	//	The flow_info and pton fields are switched in Syzkaller
	switch syzType.TypeName {
	case "sockaddr_in6":
		log.Logf(5, "Reordering in6")
		field2 := traceType.Elems[2]
		traceType.Elems[2] = traceType.Elems[3]
		traceType.Elems[3] = field2
	case "bpf_insn_generic", "bpf_insn_exit", "bpf_insn_alu", "bpf_insn_jmp", "bpf_insn_ldst":
		log.Logf(2, "bpf_insn_generic size: %d, typsize: %d", syzType.Size(), syzType.TypeSize)
		field1 := traceType.Elems[1].(parser.Expression)
		field2 := traceType.Elems[2].(parser.Expression)
		reg := (field1.Eval(ctx.Target)) | (field2.Eval(ctx.Target) << 4)
		newFields := make([]parser.IrType, len(traceType.Elems)-1)
		newFields[0] = traceType.Elems[0]
		newFields[1] = parser.NewIntsType([]int64{int64(reg)})
		newFields[2] = traceType.Elems[3]
		newFields[3] = traceType.Elems[4]
		traceType.Elems = newFields
	}
}

func shouldSkip(ctx *Context) bool {
	syscall := ctx.CurrentStraceCall
	if utils.ShouldSkip[syscall.CallName] {
		return true
	}
	// syzkaller refuses programs that open an absolute path (it treats them as
	// sandbox escapes, see prog/validation.go "escaping filename"). Process
	// startup (ld.so, CUDA libraries) produces many such calls, and keeping any
	// of them makes the whole program unloadable, so drop them here. Device
	// nodes are exempt: they are rebound to syz_open_dev$* by the open hooks and
	// are the calls we actually want to fuzz.
	if isAbsolutePathOpen(syscall) && !isKnownDevice(ctx, syscall) {
		log.Logf(3, "Skipping absolute-path open: %s", syscall.CallName)
		return true
	}
	if isUnixAbsSocket(syscall) {
		log.Logf(3, "Skipping absolute-path unix socket: %s", syscall.CallName)
		return true
	}
	switch syscall.CallName {
	case "write":
		switch a := syscall.Args[0].(type) {
		case parser.Expression:
			val := a.Eval(ctx.Target)
			if val == 1 || val == 2 {
				return true
			}
		}
	}
	return false
}
