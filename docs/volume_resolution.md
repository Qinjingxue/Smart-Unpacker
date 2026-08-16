# Structure-first volume resolution

SunPack resolves archive volumes in two deliberately bounded phases. Initial discovery is
strict and cheap, followed immediately by one structure-driven completion attempt for an
incomplete strong-anchor group; a failed extraction may request the same bounded resolver once
more after the directory contents have changed.
There is no general resolution loop and no filename-only camouflage grouping.

## Pipeline contract

```mermaid
flowchart LR
    FS["Filesystem snapshot"] --> A["Rust batched volume-anchor probe"]
    A --> R1["Relations strict grouping"]
    R1 --> D1["Detection"]
    D1 --> P1["Input planning"]
    P1 --> X1["Extraction"]
    X1 -->|"success"| Done["Continue pipeline"]
    X1 -->|"missing-volume evidence"| R2["Relations resolve once"]
    R2 --> D2["Detection"]
    D2 --> P2["Input planning"]
    P2 --> X2["One extraction retry"]
    X2 -->|"success"| Done
    X2 -->|"failure"| Report["Repair or final failure report"]
```

The retry is guarded by `relation.volume_retry_attempted`. A replacement task reuses the
logical task identity, output directory and path lease, but is required to pass Detection and
Input Planning again. The resolver must add at least one path and produce a first volume.

## Evidence and naming policy

The native probe returns a `VolumeAnchor` for each candidate. Strong evidence includes a
validated 7z Start Header CRC, ZIP local header or exact-at-end EOCD, and RAR main-volume
header information. A leading gzip, bzip2, xz, zstd or TAR structure marks the
file as a standalone stream and excludes it from another archive's volume search.

Initial Relations grouping accepts only strict conventional names. On the one retry:

1. Select a strong multi-volume anchor from the failed task.
2. Probe every sibling through the native batch API.
3. Accept structure-confirmed members of the same format and reject every structurally
   identified foreign format.
4. For formats whose middle parts are raw bytes, use the confirmed anchor's primary stem,
   archive-family token and nearby volume number to admit otherwise structureless members.
   A generic `partN`/numeric member is allowed only when that primary stem has exactly one
   structure-confirmed archive format in the directory; mixed-format stems require the format
   token and therefore cannot cross-merge.
   If multiple archives of the same format share that primary stem, a stable discriminator token
   must be shared by the anchor and its candidate members. The discriminator becomes part of the
   logical task identity; without one the result is reported as ambiguous rather than guessed.
5. Do not apply constrained filename matching when no strong anchor exists. Ordinary native
   RAR volume sets remain structure-only; only a structurally confirmed RAR SFX first chunk may
   constrain opaque numbered continuations produced by a generic byte splitter.

The relaxed decorated-name parsers are private to step 4. Canonical modern split-ZIP `.z01`,
`.z02`, ... names are strict relations; decorated variants remain private recovery evidence.

Volume evidence is private to Relations. It is used to replace matching physical-file
candidates with one logical `ArchiveInputDescriptor`, then exposed only as diagnostic
`relation.volume_anchor` metadata. Detection never accepts, rejects, scores, filters or carves
a candidate from that anchor. It evaluates the logical input through its ordinary processors
and rules; repeated structural reads are absorbed by the native reader/session caches.

## Format matrix

| Format | Structure-bearing volumes | Conventional names | Retry fallback |
|---|---|---|---|
| 7z split | First part has the 7z Start Header; middle and tail parts can be raw bytes | `.7z.001`, `.7z.002`, ... | Anchor-constrained matching for raw members |
| ZIP raw split | First part has local-file structure; terminal part has an EOCD; middle parts can be raw bytes | `.zip.001`, `.zip.002`, ... | Anchor-constrained matching for raw members |
| ZIP split archive | First `.z01` starts with the split marker and local header; terminal `.zip` EOCD carries the zero-based disk number; middle `.zNN` parts can be opaque | `.z01`, `.z02`, ..., `.zip` | Structure-first grouping plus anchor-constrained decorated `.zNN` recovery |
| RAR4/RAR5 volume set | Every native volume carries a RAR marker; ordinary RAR5 exposes its internal volume number, while header-encrypted RAR5 exposes a CRC-protected type-4 encryption header and relies on anchor-constrained naming for order | `.part1.rar`, `.part2.rar`, ...; supported strict legacy RAR naming remains available | Structure first; opaque ordinary RAR members are not admitted |
| RAR SFX volume set | First volume may have an `MZ` stub before the RAR structure; later native volumes still carry RAR structure | `.part1.exe`, `.part2.rar`, ... | Structure first |
| 7-Zip SFX plus volumes | Current 7-Zip emits a separate SFX launcher beside an ordinary `.7z.001`, `.7z.002`, ... set | `.exe` plus `.7z.001`, ... | The archive set follows normal 7z rules; the launcher is not misclassified as a data volume |
| Opaque 7z/ZIP SFX split | Strong embedded first anchor plus opaque numbered continuations | Decorated format/part/volume numbering | Anchor-constrained matching and structural upper bounds |
| Generic byte-split RAR SFX | Strong embedded RAR SFX anchor plus opaque numbered continuations | Decorated format/part/volume numbering | SFX-anchor-constrained matching; ordinary RAR cannot use this fallback |

References: [7-Zip recovery and volume layout](https://www.7-zip.org/recover.html),
[7-Zip volume switch](https://documentation.help/7-Zip-15.14/volume.htm),
[RAR 5.0 archive format](https://www.rarlab.com/technote.htm),
[RAR volume naming](https://www.rarlab.com/rar_file.htm), and
[Bandizip current split-ZIP documentation](https://en.bandisoft.com/bandizip/howto/open-z01/).

## I/O and cache guarantees

All probing is implemented in Rust and opens data through the existing `ManagedReader`.
Ordinary files read at most a 512-byte head and 65,557-byte tail. Only a leading `MZ`
candidate receives an expanded prefix scan, capped at 1 MiB, for an embedded SFX signature.
No probe scales with archive or volume size, and directory-wide resolution does not create a
parallel extraction workload.

Use the shared benchmark harness to measure this contract:

```powershell
python -m benchmarks reader volume-anchor --files 128 --logical-mib 64 --rounds 5
```

The benchmark creates sparse temporary candidates, writes the versioned report beneath
`benchmarks/results/reader.volume-anchor/`, and removes its temporary corpus on exit.

## Regression corpus

The real-archive integration test builds 7z, ZIP and RAR volumes with the bundled tools. Every
part is larger than 1 MiB. All formats are moved into one directory and renamed with one shared
primary stem, format-specific volume markers, arbitrary noise and fake suffixes. Resolution and
extraction run one format at a time, then the full pipeline verifies one and only one regrouping
attempt before Repair.
