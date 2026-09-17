.PHONY: all build generate test vet fmt clean

# The syzkaller API comes from the modern tree at ../syzkaller via the go.mod
# replace directive; the old vendor/ tree is no longer used. Requires go 1.26+.
GO ?= go

all: build

build:
	$(GO) build -o ./bin/trace2syz .

# Regenerate the ragel/goyacc parsers from their sources. The generated files
# are checked in (they carry the fork's kcov "Cover:" handling), so this is only
# needed after editing parser/straceLex.rl or parser/strace.y.
generate:
	cd parser && ragel -Z -G2 -o lex.go straceLex.rl
	cd parser && goyacc -o strace.go -p Strace strace.y

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w $$(gofmt -l . | grep -v 'lex\.go$$' | grep -v 'strace\.go$$')

clean:
	rm -rf bin deserialized corpus.db
