# Local go-libp2p patches

`pkg/go-libp2p` is a **modified copy of upstream go-libp2p**, wired in through

```
replace github.com/libp2p/go-libp2p v0.50.0 => ./pkg/go-libp2p
```

The copy itself is **not versioned** (760 files / 6 MB of upstream source would
be re-uploaded on every patch bump). What is versioned here is:

| file | purpose |
|---|---|
| `UPSTREAM` | the exact upstream release the patch applies to (tag + commit SHA) |
| `p2ptap-v0.50.0.patch` | unified diff: upstream `v0.50.0` → the tree we build against |
| `LOCAL_PATCHES.md` | why each hunk exists, including the ones that were tried and reverted |

## Materialising the tree

```sh
# POSIX (CI, macOS, Linux, Git Bash)
./scripts/fetch-libp2p.sh

# Windows
powershell -ExecutionPolicy Bypass -File .\scripts\fetch-libp2p.ps1
```

Both scripts are idempotent: they only rebuild `pkg/go-libp2p` when it is
missing, and `--force` / `-Force` re-materialises it from scratch (needed after
moving the pin or regenerating the patch).

`pkg/go-libp2p` is listed in `.gitignore`. A fresh clone therefore has no
`pkg/go-libp2p` until the script runs — `go build ./...` will fail until then,
which is intentional: a silent fallback to unpatched upstream would compile but
lose the socket-binding, WebRTC buffer and QUIC/TLS behaviour this project
depends on.

## Regenerating the patch (when bumping upstream)

```sh
git clone --depth 1 --branch v0.50.0 https://github.com/libp2p/go-libp2p /tmp/lp2p-base
rm -rf /tmp/lp2p-base/.git
# keep the OLD patched tree as the target: patches are the delta, not a snapshot
diff -ruN --exclude=.github --exclude=examples --exclude=test-plans --exclude=scripts \
     /tmp/lp2p-base pkg/go-libp2p > patches/go-libp2p/p2ptap-<newver>.patch
```

Then update `UPSTREAM` (tag + `git rev-parse HEAD` of the clone) and re-run the
fetch script with `--force`.

`diff -ruN` emits `--- lp2p-base/<path>` / `+++ pkg/go-libp2p/<path>` headers, so
the patch applies with a one-component strip **from inside `pkg/go-libp2p`**,
which is what the fetch scripts do (`git apply -p1`).

### Excluded subtrees

`.github/`, `examples/`, `test-plans/` and `scripts/` are left exactly as
upstream ships them. They are separate modules / CI config / dev tooling that the
p2ptap build never imports, and their only local differences are incidental
go-version drift from the snapshot the fork was taken from — noise in a patch
whose job is to describe *behavioural* changes.

## Applying by hand

```sh
cd pkg/go-libp2p
git apply -p1 --whitespace=nowarn ../../patches/go-libp2p/p2ptap-v0.50.0.patch
```

`patch -p1 < …` works too. The patch contains no binary hunks and no renames, so
either tool applies it deterministically.
