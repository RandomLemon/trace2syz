# trace2syz

Converts strace output into syzkaller programs. Adapted from
[MoonShine](https://github.com/shankarapailoor/moonshine).

This tree is a fork maintained for the TensorFunnel GPU-fuzzing pipeline. It is vendored into that
repo as the `trace2syz/` submodule and **builds against the modern syzkaller** (Go 1.26, module
mode) rather than a private copy of the 2018 one.

## Build and run

Requires Go 1.26+; `ragel`/`goyacc` are only needed for `make generate`.

```bash
make                 # go build -o ./bin/trace2syz .
make test            # go test ./...
make generate        # regenerate parser/{lex,strace}.go from the .rl/.y sources
make vet
make fmt
make clean
```

```bash
./bin/trace2syz -file /path/to/trace          # single trace
./bin/trace2syz -dir /path/to/tracedir        # every file in a directory
```

It writes the converted programs to `deserialized/` and packs them into `corpus.db`. Verify the
result before feeding it to syzkaller — `syz-manager` silently deletes programs that fail to
deserialize:

```bash
cd ../syzkaller
go run ./tools/nvidia_corpus_check ../trace2syz/corpus.db     # expect: ok=1 bad=0
```

## How the syzkaller dependency is wired

`go.mod` pins it with a relative replace:

```
replace github.com/google/syzkaller => ../syzkaller
```

so the module resolves from any checkout location and always tracks the sibling `syzkaller/`
submodule. The old `vendor/github.com/google/syzkaller/` tree has been removed: it held a trimmed,
**old-format** copy of syzkaller, and keeping it in sync with the modern one was a recurring source
of `unknown syscall ioctl$NV_ESC_*` errors. There is now a single source of descriptions.

## Capture traces

```bash
strace -o tf.trace -s 65500 -v -xx -f -k ./payload
```

Do **not** add `-y`: it turns `3` into `3</dev/nvidia0>`, which makes the parser fail with
`syntax error`. Device routing is already done inside strace.

## What this fork adds over upstream

- `"Cover:"` (KCOV) line handling in the scanner, so per-call coverage reaches the distillers.
- `_IOC` macro evaluation, so `ioctl(..., _IOC(_IOC_READ|_IOC_WRITE, 0x46, 0x2a, 0x20), ...)`
  resolves to a numeric command.
- Device binding: `open()`/`openat()` of a node matching a `syz_open_dev` pattern is rebound to the
  matching `syz_open_dev$<dev>` variant, while non-device absolute paths are dropped (syzkaller
  rejects them as sandbox escapes and would delete the whole program).
- `dup`/`dup2`/`dup3` keep the device identity of the source descriptor
  (`dup$nvidia`, `dup$nvidiactl`, …) instead of collapsing to a generic `fd`.
- Variant selection by value for `ioctl`, `fcntl`, `bpf`, `socket`, `getsockopt`/`setsockopt` and
  the connection calls.

The generated parsers (`parser/lex.go`, `parser/strace.go`) are **checked in** because they carry
the KCOV and `_IOC` behaviour above; regenerate them with `make generate` after editing the `.rl`/
`.y` sources.

## Layout

| Path | Contents |
|---|---|
| `main.go` | CLI: parse traces, validate, emit `deserialized/` + `corpus.db` |
| `parser/` | strace scanner (`lex.rl`/`lex.go`), grammar (`strace.y`/`strace.go`), IR types |
| `proggen/` | IR → syzkaller program generation, variant/preprocess hooks, memory tracking |
| `utils/` | Skip lists and strace constant fallbacks |
