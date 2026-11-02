# Published `stb_image` GIF regression: reproduction record

This is a validation of a previously disclosed issue, not a new vulnerability
report. It is tracked as [CVE-2026-5185](https://nvd.nist.gov/vuln/detail/CVE-2026-5185).
The upstream report describes an out-of-bounds read in animated GIF frame
composition (`stbi__gif_load_next`, `two_back` pointer) when processing a
crafted multi-frame GIF, with possible crash or information disclosure. See
[upstream issue #1915](https://github.com/nothings/stb/issues/1915) and its
related [memory-safety report #1928](https://github.com/nothings/stb/issues/1928).

## Reproduction result

Input: `corpus/known_public_gif_regression.gif` (117 bytes; SHA-256
`578a9d11ef88f64b614276c7b4e74b016c79cffd6c30851ff098b55c4d579ec9`), obtained
from the public PoC collection at
[boergeson/stb/poc](https://github.com/boergeson/stb/tree/fix/memory-safety-issues/poc).

Both runs used the same libFuzzer + AddressSanitizer + UndefinedBehaviorSanitizer
harness, and the same resource-limited, network-disabled Docker environment:

| Source snapshot | Result |
| --- | --- |
| Older upstream `master`, `003501f6d7a8668ce8b6d875e34dd97ad0d5d5b5` | ASan: `heap-use-after-free`, `READ of size 4`; process aborted (exit 1) |
| Pinned upstream `dev`, `608de2239da15d9635920e3e77d664d9c13189cd` | Same input completed; no ASan/UBSan report (exit 0) |

The older-snapshot trace had an unavailable external symbolizer, so it shows
addresses rather than source line numbers. ASan still classifies the fault as a
heap use-after-free and records the read, free, and allocation stacks. The
public report categorizes the root cause as an out-of-bounds read; our result
is consistent with that memory-safety failure but does not independently
establish exploitability or real-world impact.

## Run the patched-snapshot check

Build the fuzzer image as described in [README.md](README.md), then from this
directory run:

```sh
mkdir -p corpus
docker run --rm --network none --memory=1536m --cpus=2 --pids-limit=64 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/corpus:/work/corpus:Z" \
  ndaynexus-stb-image-fuzzer \
  /work/corpus/known_public_gif_regression.gif -runs=1
```

To reproduce the older snapshot, run this from this directory. The expected
ASan report makes the inner command return nonzero; the wrapper removes its
temporary executable and returns zero after displaying that expected report.

```sh
docker run --rm --network none --memory=1536m --cpus=2 --pids-limit=64 \
  --read-only --tmpfs /tmp:rw,nosuid,size=256m \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/corpus:/work/corpus:Z" \
  --entrypoint /bin/bash ndaynexus-stb-image-fuzzer -lc \
  'git -C /opt/stb -c safe.directory=/opt/stb show 003501f6d7a8668ce8b6d875e34dd97ad0d5d5b5:stb_image.h > /tmp/stb_image.h && clang -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined -I /tmp /opt/fuzz_stb_image.c -o /work/corpus/.fuzz_master && /work/corpus/.fuzz_master /work/corpus/known_public_gif_regression.gif -runs=1; rc=$?; rm -f /work/corpus/.fuzz_master; echo MASTER_EXIT=$rc; exit 0'
```

Do not publish the old header or describe this known issue as a project
discovery; cite the upstream report.

## What this proves

It demonstrates that the local harness reaches the animated GIF path, that
sanitizers can detect the reported invalid memory access, and that this input
does not trigger the same finding in the selected `dev` snapshot. It does not
prove all GIFs or all image formats are safe, that `dev` is a stable release,
or that a new vulnerability has been found. A clean single-input check is only
regression evidence.
