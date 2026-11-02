# Source review notes

## Scope

Reviewed the pinned upstream `stb_image.h` snapshot
`608de2239da15d9635920e3e77d664d9c13189cd` (2026-11-01) and compared it with
the earlier upstream `master` snapshot
`003501f6d7a8668ce8b6d875e34dd97ad0d5d5b5`. The source-only diff and header
copies are in the ignored `upstream_seeds/` scratch directory. This is a
focused source review, not a complete audit of every compile-time option or
platform-specific path.

## Known memory-safety cases checked

The recent [upstream report #1928](https://github.com/nothings/stb/issues/1928)
lists integer-overflow, out-of-bounds, GIF frame-accounting, palette, PNG
validation, JPEG marker, and uninitialized-data issues. The maintainer says the
reported cases were fixed on `dev`. I checked representative current code paths:

- Output-size conversions use checked `stbi__mad* sizes_valid` helpers before
  allocation. In particular, the 16-bit output converter now uses the
  four-factor checked allocator.
- GIF frame accumulation checks addition in `totalbytes`, allocates the final
  frame stack with checked multiplication, and no longer uses the old
  `two_back` pointer calculation.
- PNG rejects sub-8-bit RGB/RGBA combinations, zero-initializes the palette
  buffer before indexed expansion, and bounds IDAT accumulation with checked
  size arithmetic and a growth limit.
- Progressive JPEG coefficient storage is initialized, and marker-processing
  failures return failure rather than success.
- BMP palette storage is initialized before lookup.

These checks confirm that those specific public cases are addressed in this
snapshot; they do not establish that neighboring code is free of other bugs.
The previously reproduced GIF issue is **CVE-2026-5185** and is excluded from
any claim of new discovery. Its before/after result is in
[KNOWN_REGRESSION.md](KNOWN_REGRESSION.md).

## Separate API behavior regression

One distinct, reproducible behavior change showed up during source comparison:

- The public API documentation says `desired_channels == 0` returns the
  source's native channel count.
- In pinned `dev`, `stbi__load_main` rejects `req_comp < 1` (header line 1161).
- A one-pixel PGM loaded with `desired_channels=0` succeeds on the old snapshot
  but fails on pinned `dev` with `bad req_comp`; the same image with
  `desired_channels=1` succeeds on `dev`.

This is an upstream development-branch API regression, **not a demonstrated
security vulnerability**. It is not CVE-2026-5185 and it is not being reported
as a novel security finding. Reproduction was performed with a small in-memory
PGM and a direct comparison build inside the isolated container. The public
contract is documented in the header around lines 153–164.

## Analysis status

- Clang Static Analyzer ran on the pinned header. It emitted 24 warnings,
  mostly path-analysis claims that decoder output buffers are uninitialized,
  plus dead-store notices. I manually followed the data paths behind the
  uninitialized-buffer warnings; they do not demonstrate a leak by themselves.
- The expanded five-minute ASan/UBSan campaign completed without a sanitizer
  finding. It exercised image loaders, animated GIF decoding, and standalone
  zlib helpers. The separate focused zlib campaign was interrupted early and
  is incomplete.
- **No new security vulnerability is confirmed.** The API regression is a
  useful concrete bug to show in a code-review presentation, but it should not
  be presented as a security vulnerability.

## References

- [Upstream report #1928 and maintainer fix status](https://github.com/nothings/stb/issues/1928)
- [CVE-2026-5185 record](https://nvd.nist.gov/vuln/detail/CVE-2026-5185)
- [Pinned source snapshot](https://github.com/nothings/stb/tree/608de2239da15d9635920e3e77d664d9c13189cd)
