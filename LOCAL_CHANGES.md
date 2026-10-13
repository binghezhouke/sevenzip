# mount123 maintenance branch

Based on upstream v1.6.1 (`a40a39ef0f29542db3d47d1dcb58d011b214feb8`).
The module path remains `github.com/bodgit/sevenzip`. The upstream BSD-3-Clause
license is unchanged.

Additions for read-only filesystem backends:

- `Reader.Streams()` returns an independent metadata snapshot of solid groups.
- `File.StreamOffset()` reports a member's uncompressed offset in `File.Stream`,
  with a boolean distinguishing streamless empty files and directories.
- `Reader.OpenStream(index)` opens a separately owned decoder from a group's
  beginning. It validates stream length and a nonzero group CRC at EOF, wraps
  decoder failures in `ReadError`, and releases the decoder directly on Close.
  Group CRCs are optional; consumers still need per-member validation where
  required. Close is idempotent, and an early Close does not validate unread data.
- `Reader.PackedRanges(index)` exposes validated absolute packed-input bounds.
- `Reader.OpenStreamWithReader(index, readerAt)` injects a body source without
  reparsing headers. The caller owns the source, including cleanup if opening
  a decoder fails. This allows bounded remote read windows independently for
  BCJ2 inputs and split archives without adding network policy to this library.
- Group content reads use a 1 MiB packed-input buffer to reduce ReaderAt calls
  for remote sources. Header decoding and existing File.Open behavior retain
  the upstream buffer size.
- `StreamLayout.AESLZMA2DecoderInfo()` recognizes the canonical serial
  AES-256-CBC to LZMA2 graph without reading source bytes or deriving a key.
  It validates properties, bindings, packed input and padding geometry, and
  exposes the existing LZMA2 costs plus a conservative 256 KiB AES charge,
  including buffer growth. `PlainLZMA2DecoderInfo()` stays unencrypted.
  These costs cover only built-in codecs, not registry overrides, KDF CPU,
  process-wide key caching or caller password storage. Existing AES Close and
  key derivation behavior is unchanged.

The fork does not manage persistent caches, credentials, scheduling, request
cancellation or cache budgets. These belong to the mount123 caller. No shared
decoder is retained after OpenStream.Close, and OpenStream does not use the
File.Open decoder pool.

Validation covers stream/member equivalence for copy, LZMA2, BCJ2, empty and
encrypted archives. The upstream suite passes normally; race checks exclude
the existing TestFS stress test, which exceeds a 120-second race-test timeout.
