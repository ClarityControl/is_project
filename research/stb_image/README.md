# Local `stb_image` fuzzing study

This is a standalone, local-only fuzzing harness. It does not add a CVE target
to N-Day Nexus and does not contact any service. It feeds generated image bytes
to `stb_image`'s in-memory decoder under libFuzzer, AddressSanitizer, and
UndefinedBehaviorSanitizer. The harness exercises native channel output and
conversion to four output channels.

## Important status before starting

The upstream repository has public memory-safety reports for `stb_image`,
including the animated GIF issue described in [issue #1915](https://github.com/nothings/stb/issues/1915)
and the broader [issue #1928](https://github.com/nothings/stb/issues/1928).
We reproduced a published GIF regression against the older `master` snapshot
and confirmed the same input runs clean against the pinned `dev` snapshot. This
validates the harness and provides a concrete before/after demonstration; it is
**not a new discovery**. See [KNOWN_REGRESSION.md](KNOWN_REGRESSION.md) for the
commands and captured results. The Docker build prints the exact upstream
commit SHA so future runs can be reproduced. Review current upstream reports
and the checked-out source revision before beginning a fresh campaign.

## Build in Docker (recommended)

Docker installs Clang and fetches the reviewed upstream branch inside the image;
it does not install packages on the Fedora host. The build prints the exact
upstream commit SHA:

```sh
docker build --build-arg STB_REF=608de2239da15d9635920e3e77d664d9c13189cd \
  -t ndaynexus-stb-image-fuzzer research/stb_image
```

Run with no network, 1.5 GiB memory, two CPU cores, and a five-minute limit.
The only writable host paths are the explicit corpus and artifact mounts:

```sh
cd research/stb_image
mkdir -p corpus artifacts
python3 make_seed_corpus.py corpus
timeout 5m docker run --rm --network none --memory=1536m --cpus=2 --pids-limit=64 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/corpus:/work/corpus:Z" \
  -v "$PWD/artifacts:/work/artifacts:Z" \
  ndaynexus-stb-image-fuzzer /work/corpus \
  -max_total_time=240 -max_len=1048576 -timeout=10 -rss_limit_mb=1200 \
  -artifact_prefix=/work/artifacts/
```

The source ref can be overridden with `--build-arg STB_REF=<reviewed-tag-or-commit>`.
Use a reviewed immutable commit SHA for repeatable runs and record the build
output. The optional host build script is available when Clang is already
installed, but Docker is the safer default.

The decoder rejects images above
8192 pixels in either dimension through `STBI_MAX_DIMENSIONS`; keep the process
resource limits as a second boundary:

Only run this against source and binaries on this machine. A sanitizer report is
a lead, not proof of a security vulnerability. Reproduce it, minimize the input,
check whether the behavior is already reported, determine impact, and follow the
upstream security reporting instructions before sharing details publicly.

## Limits of this first version

This is a small memory-safety fuzz harness, not a complete vulnerability
discovery system. It has only a starter seed corpus, no coverage dashboard, or
cross-version differential oracle yet. It also deliberately caps dimensions,
so it will not exercise code paths requiring images above that limit. Results
need manual triage, and a clean run does not establish that the library is safe.
The manual review status and the distinct API regression observed in the pinned
snapshot are recorded in [AUDIT_NOTES.md](AUDIT_NOTES.md).

## Fuzzing status

The first five-minute campaign (13,902 executions, 1,941 coverage counters,
about 481 MiB peak RSS) used an earlier harness that did not call the animated
GIF sequence API. It found no sanitizer issue. The expanded five-minute run
covered the sequence API and standalone zlib helpers; it completed 5,229 runs
with no sanitizer finding. A focused zlib run was stopped before its planned
end when the review was redirected to manual code analysis; it had no finding
at that point. The published GIF regression check is separate: it triggers an
ASan heap-use-after-free in the older snapshot and exits cleanly on pinned
`dev`. No new security vulnerability has been confirmed.
