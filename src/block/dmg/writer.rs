//! UDIF (`.dmg`) writer — encode a sector stream into a single-segment
//! Apple disk image.
//!
//! The writer is deliberately *only* a container encoder. It takes
//! 512-byte sectors from the caller (directly through
//! [`UdifWriter::write_sectors`], or pulled from a [`BlockDevice`] / a
//! [`Read`] of known length by [`write_udif`] / [`write_udif_from_reader`])
//! and writes the image into a caller-owned [`Write`] + [`Seek`] sink. It
//! never creates, renames, syncs or publishes files: a caller building a
//! release artefact writes into a temporary file, gets the sink back from
//! [`UdifWriter::finish`], syncs/closes it, signs it, and only then moves
//! it into place.
//!
//! ## What gets written
//!
//! ```text
//!   [ data fork: chunk payloads in sector order        ]
//!   [ XML plist: resource-fork → blkx[..] + plst[0]    ]
//!   [ 512-byte koly trailer                            ]
//! ```
//!
//! The `blkx` array follows [`UdifWriteOptions::layout`]:
//!
//! - [`UdifLayout::WholeDevice`] (the default) — one entry covering the
//!   whole device, as `hdiutil` writes for a `-layout NONE` image: named
//!   `whole disk (Apple_HFS : 0)` (configurable), `ID` 0, block
//!   descriptor `-2`.
//! - [`UdifLayout::Map`] — one entry per region of a partitioned disk
//!   (partition-table structures, partitions, free space), as `hdiutil`
//!   writes for a GPT / APM / MBR image. [`udif_partition_map`] builds the
//!   map from a device's partition table with `hdiutil`'s names and IDs.
//! - [`UdifLayout::Auto`] — [`write_udif`] probes its source for a
//!   partition table and picks one of the two.
//!
//! Every entry has attributes `0x0050`. Each chunk covers at most
//! [`UdifWriteOptions::chunk_sectors`] sectors and never crosses an entry
//! boundary. All-zero sectors are never compressed — runs of them become
//! zero-fill (`0x00000000`) or, on request (and always inside free-space
//! entries or under MD5 checksums), "ignore" (`0x00000002`) entries.
//! UFBI is the exception: it stores every sector. A data chunk whose encoding
//! would not be smaller than its plaintext is stored raw (`0x00000001`),
//! as `hdiutil` does. The constant `plst` resource `hdiutil` adds to every
//! image is written too.
//!
//! ## Checksums
//!
//! With [`UdifChecksum::Crc32`] (the default) or [`UdifChecksum::Md5`] the
//! writer records, exactly as `hdiutil` does:
//!
//! - one partition checksum per `blkx` entry, in its mish header — over
//!   the entry's plaintext sectors, *excluding* sectors carried by
//!   "ignore" entries;
//! - the data-fork checksum in the trailer — over the data-fork bytes as
//!   stored;
//! - the master checksum in the trailer — over the concatenated partition
//!   checksums (big-endian CRC-32s, or the 16-byte MD5 digests).
//!
//! ## Formats
//!
//! | [`UdifFormat`] | chunk codec | Cargo feature |
//! |---|---|---|
//! | `Udro` | raw | `dmg-write` |
//! | `Udco` | ADC (built in) | `dmg-write` |
//! | `Ufbi` | raw, every sector stored, MD5 checksums | `dmg-write` |
//! | `Udrw` | bare sectors, no UDIF metadata | `dmg-write` |
//! | `Udzo` | zlib | `dmg-write-zlib` |
//! | `Udbz` | bzip2 | `dmg-write-bzip2` |
//! | `Ulmo` | LZMA (XZ-framed, as current `hdiutil` writes) | `dmg-write-lzma` |
//! | `Ulfo` | LZFSE | `dmg-write-lzfse` |
//!
//! A format whose codec feature is compiled out (or, for ULFO, whose
//! encoder doesn't exist yet) is refused by [`UdifWriter::new`] with
//! [`crate::Error::Unsupported`] naming the cause, before anything is
//! written.

use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Seek, Write};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread::JoinHandle;

pub use super::layout::udif_partition_map;
use super::mish::{CHUNK_LEN, ChunkType, MISH_HEADER_LEN, MISH_MAGIC};
use super::{KOLY_MAGIC, KOLY_SIZE, KolyTrailer, MAX_CHUNK_SECTORS};
use crate::Result;
use crate::block::BlockDevice;
use crate::md5::Md5;

/// Opt-in UDIF write-pipeline counters (`FSTOOL_UDIF_STATS=1`), compiled
/// only with the `udif-stats` feature. The no-op version keeps call sites
/// free of `cfg` noise in normal builds.
#[cfg(feature = "udif-stats")]
mod udif_stats {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use super::{MAX_WRITE_THREADS, SECTOR};

    const BUCKETS: usize = 40;

    pub struct Stats {
        inner: Option<Arc<Inner>>,
    }

    impl Clone for Stats {
        fn clone(&self) -> Self {
            if let Some(inner) = &self.inner {
                inner.owners.fetch_add(1, Ordering::Relaxed);
            }
            Self {
                inner: self.inner.clone(),
            }
        }
    }

    impl Drop for Stats {
        fn drop(&mut self) {
            if let Some(inner) = &self.inner
                && inner.owners.fetch_sub(1, Ordering::AcqRel) == 1
            {
                // Last API handle: stop the reporter even if the writer was
                // dropped without reaching `finish`.
                inner.stop.store(true, Ordering::Relaxed);
            }
        }
    }

    struct Inner {
        start: Instant,
        /// Number of live `Stats` handles. The reporter thread itself holds
        /// an `Arc<Inner>`, so it cannot use the strong count for this.
        owners: AtomicUsize,
        sectors: AtomicU64,
        published: AtomicU64,
        zero_sectors: AtomicU64,
        data_sectors: AtomicU64,
        data_bytes: AtomicU64,
        out_bytes: AtomicU64,
        jobs: AtomicU64,
        done: AtomicU64,
        active: AtomicU64,
        enc_nanos: AtomicU64,
        read_nanos: AtomicU64,
        out_nanos: AtomicU64,
        window_nanos: AtomicU64,
        finalize_nanos: AtomicU64,
        ready: AtomicU64,
        lag: AtomicU64,
        workers: AtomicU64,
        queued: [AtomicU64; MAX_WRITE_THREADS],
        min_bytes: AtomicU64,
        max_bytes: AtomicU64,
        max_enc_nanos: AtomicU64,
        hist: [AtomicU64; BUCKETS],
        enc_hist: [AtomicU64; BUCKETS],
        stop: AtomicBool,
        #[cfg(test)]
        alive: Arc<AtomicBool>,
    }

    impl Stats {
        pub fn from_env() -> Self {
            let enabled =
                std::env::var_os("FSTOOL_UDIF_STATS").is_some_and(|v| !v.is_empty() && v != "0");
            Self::start(enabled)
        }

        fn start(enabled: bool) -> Self {
            if !enabled {
                return Self { inner: None };
            }
            let inner = Arc::new(Inner {
                start: Instant::now(),
                owners: AtomicUsize::new(1),
                sectors: AtomicU64::new(0),
                published: AtomicU64::new(0),
                zero_sectors: AtomicU64::new(0),
                data_sectors: AtomicU64::new(0),
                data_bytes: AtomicU64::new(0),
                out_bytes: AtomicU64::new(0),
                jobs: AtomicU64::new(0),
                done: AtomicU64::new(0),
                active: AtomicU64::new(0),
                enc_nanos: AtomicU64::new(0),
                read_nanos: AtomicU64::new(0),
                out_nanos: AtomicU64::new(0),
                window_nanos: AtomicU64::new(0),
                finalize_nanos: AtomicU64::new(0),
                ready: AtomicU64::new(0),
                lag: AtomicU64::new(0),
                workers: AtomicU64::new(0),
                queued: std::array::from_fn(|_| AtomicU64::new(0)),
                min_bytes: AtomicU64::new(u64::MAX),
                max_bytes: AtomicU64::new(0),
                max_enc_nanos: AtomicU64::new(0),
                hist: std::array::from_fn(|_| AtomicU64::new(0)),
                enc_hist: std::array::from_fn(|_| AtomicU64::new(0)),
                stop: AtomicBool::new(false),
                #[cfg(test)]
                alive: Arc::new(AtomicBool::new(true)),
            });
            let report = Arc::clone(&inner);
            let _ = std::thread::Builder::new()
                .name("fstool-udif-stats".into())
                .spawn(move || {
                    let mut next = Duration::from_secs(1);
                    loop {
                        std::thread::sleep(Duration::from_millis(200));
                        if report.stop.load(Ordering::Relaxed) {
                            break;
                        }
                        if report.start.elapsed() >= next {
                            next += Duration::from_secs(1);
                            print_stats(&report);
                        }
                    }
                    #[cfg(test)]
                    report.alive.store(false, Ordering::Relaxed);
                });
            Self { inner: Some(inner) }
        }

        /// Start an always-enabled reporter and return a liveness flag the
        /// test can poll after dropping the handles.
        #[cfg(test)]
        pub fn for_test() -> (Self, Arc<AtomicBool>) {
            let stats = Self::start(true);
            let alive = Arc::clone(
                &stats
                    .inner
                    .as_ref()
                    .expect("enabled stats have an inner")
                    .alive,
            );
            (stats, alive)
        }

        fn inner(&self) -> Option<&Inner> {
            self.inner.as_deref()
        }

        pub fn add_source_sectors(&self, n: u64) {
            if let Some(i) = self.inner() {
                i.sectors.fetch_add(n, Ordering::Relaxed);
            }
        }

        pub fn add_published_sectors(&self, n: u64) {
            if let Some(i) = self.inner() {
                i.published.fetch_add(n, Ordering::Relaxed);
            }
        }

        pub fn add_zero_sectors(&self, n: u64) {
            if let Some(i) = self.inner() {
                i.zero_sectors.fetch_add(n, Ordering::Relaxed);
            }
        }

        pub fn add_data_sectors(&self, n: u64) {
            if let Some(i) = self.inner() {
                i.data_sectors.fetch_add(n, Ordering::Relaxed);
            }
        }

        pub fn job_submitted(&self, bytes: usize) {
            if let Some(i) = self.inner() {
                let b = bytes as u64;
                i.jobs.fetch_add(1, Ordering::Relaxed);
                i.data_bytes.fetch_add(b, Ordering::Relaxed);
                i.min_bytes.fetch_min(b, Ordering::Relaxed);
                i.max_bytes.fetch_max(b, Ordering::Relaxed);
                i.hist[bucket(bytes).min(BUCKETS - 1)].fetch_add(1, Ordering::Relaxed);
            }
        }

        pub fn job_start(&self) {
            if let Some(i) = self.inner() {
                i.active.fetch_add(1, Ordering::Relaxed);
            }
        }

        pub fn job_end(&self, nanos: u64) {
            if let Some(i) = self.inner() {
                i.active.fetch_sub(1, Ordering::Relaxed);
                i.done.fetch_add(1, Ordering::Relaxed);
                i.enc_nanos.fetch_add(nanos, Ordering::Relaxed);
                i.max_enc_nanos.fetch_max(nanos, Ordering::Relaxed);
                i.enc_hist[bucket64(nanos).min(BUCKETS - 1)].fetch_add(1, Ordering::Relaxed);
            }
        }

        pub fn job_emitted(&self, bytes: usize) {
            if let Some(i) = self.inner() {
                i.out_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
            }
        }

        pub fn ready(&self, n: u64) {
            if let Some(i) = self.inner() {
                i.ready.store(n, Ordering::Relaxed);
            }
        }

        pub fn lag(&self, n: u64) {
            if let Some(i) = self.inner() {
                i.lag.store(n, Ordering::Relaxed);
            }
        }

        pub fn init_workers(&self, n: usize) {
            if let Some(i) = self.inner() {
                i.workers.store(n as u64, Ordering::Relaxed);
            }
        }

        pub fn worker_sent(&self, index: usize) {
            if let Some(q) = self.inner().and_then(|i| i.queued.get(index)) {
                q.fetch_add(1, Ordering::Relaxed);
            }
        }

        pub fn worker_started(&self, index: usize) {
            if let Some(q) = self.inner().and_then(|i| i.queued.get(index)) {
                q.fetch_sub(1, Ordering::Relaxed);
            }
        }

        pub fn worker_cancelled(&self, index: usize) {
            if let Some(q) = self.inner().and_then(|i| i.queued.get(index)) {
                q.fetch_sub(1, Ordering::Relaxed);
            }
        }

        pub fn read_wait(&self, d: Duration) {
            if let Some(i) = self.inner() {
                i.read_nanos
                    .fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
            }
        }

        pub fn write_out(&self, d: Duration) {
            if let Some(i) = self.inner() {
                i.out_nanos
                    .fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
            }
        }

        pub fn wait_window(&self, d: Duration) {
            if let Some(i) = self.inner() {
                i.window_nanos
                    .fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
            }
        }

        pub fn wait_finalize(&self, d: Duration) {
            if let Some(i) = self.inner() {
                i.finalize_nanos
                    .fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
            }
        }

        pub fn report(&self) {
            if let Some(i) = self.inner() {
                print_stats(i);
            }
        }

        pub fn stop(&self) {
            if let Some(i) = self.inner() {
                i.stop.store(true, Ordering::Relaxed);
            }
        }
    }

    fn bucket(bytes: usize) -> usize {
        bucket64(bytes as u64)
    }

    fn bucket64(v: u64) -> usize {
        if v == 0 {
            0
        } else {
            (u64::BITS - v.leading_zeros() - 1) as usize
        }
    }

    fn pct(hist: &[AtomicU64; BUCKETS], p: u64) -> u64 {
        let total: u64 = hist.iter().map(|c| c.load(Ordering::Relaxed)).sum();
        if total == 0 {
            return 0;
        }
        let want = (total * p).div_ceil(100);
        let mut seen = 0;
        for (b, c) in hist.iter().enumerate() {
            seen += c.load(Ordering::Relaxed);
            if seen >= want {
                return if b == 0 { 0 } else { 1u64 << b };
            }
        }
        0
    }

    fn mib(n: u64) -> f64 {
        n as f64 / (1024.0 * 1024.0)
    }

    fn ms(n: u64) -> f64 {
        n as f64 / 1e6
    }

    fn print_stats(i: &Inner) {
        let hist = &i.hist;
        let total: u64 = hist.iter().map(|c| c.load(Ordering::Relaxed)).sum();
        let small: u64 = (0..16).map(|b| hist[b].load(Ordering::Relaxed)).sum();
        let min = match i.min_bytes.load(Ordering::Relaxed) {
            u64::MAX => 0,
            v => v,
        };
        let max = i.max_bytes.load(Ordering::Relaxed);
        let workers = (i.workers.load(Ordering::Relaxed) as usize).min(MAX_WRITE_THREADS);
        let q = (0..workers)
            .map(|idx| i.queued[idx].load(Ordering::Relaxed).to_string())
            .collect::<Vec<_>>()
            .join(",");
        let e50 = pct(&i.enc_hist, 50) / 1_000_000;
        let e95 = pct(&i.enc_hist, 95) / 1_000_000;
        let emax = i.max_enc_nanos.load(Ordering::Relaxed) / 1_000_000;
        eprintln!(
            "udif-stats {:>7.1}s src={:>9.1}MiB pub={:>9.1}MiB zero={:>9.1}MiB \
             data={:>9.1}MiB sub={:>9.1}MiB fork={:>9.1}MiB | jobs={} done={} \
             active={} ready={} lag={} | size min={}KiB p50={}KiB p95={}KiB \
             max={}KiB small64K={}/{} | wait read={:.0}ms out={:.0}ms \
             win={:.0}ms fin={:.0}ms | q=[{}] enc p50={}ms p95={}ms max={}ms \
             total={:.1}s",
            i.start.elapsed().as_secs_f64(),
            mib(i.sectors.load(Ordering::Relaxed) * SECTOR as u64),
            mib(i.published.load(Ordering::Relaxed) * SECTOR as u64),
            mib(i.zero_sectors.load(Ordering::Relaxed) * SECTOR as u64),
            mib(i.data_sectors.load(Ordering::Relaxed) * SECTOR as u64),
            mib(i.data_bytes.load(Ordering::Relaxed)),
            mib(i.out_bytes.load(Ordering::Relaxed)),
            i.jobs.load(Ordering::Relaxed),
            i.done.load(Ordering::Relaxed),
            i.active.load(Ordering::Relaxed),
            i.ready.load(Ordering::Relaxed),
            i.lag.load(Ordering::Relaxed),
            min / 1024,
            pct(hist, 50) / 1024,
            pct(hist, 95) / 1024,
            max / 1024,
            small,
            total,
            ms(i.read_nanos.load(Ordering::Relaxed)),
            ms(i.out_nanos.load(Ordering::Relaxed)),
            ms(i.window_nanos.load(Ordering::Relaxed)),
            ms(i.finalize_nanos.load(Ordering::Relaxed)),
            q,
            e50,
            e95,
            emax,
            i.enc_nanos.load(Ordering::Relaxed) as f64 / 1e9,
        );
    }
}

#[cfg(not(feature = "udif-stats"))]
mod udif_stats {
    use std::time::Duration;

    #[derive(Clone, Copy)]
    pub struct Stats;

    impl Stats {
        pub fn from_env() -> Self {
            Self
        }
        pub fn add_source_sectors(&self, _n: u64) {}
        pub fn add_published_sectors(&self, _n: u64) {}
        pub fn add_zero_sectors(&self, _n: u64) {}
        pub fn add_data_sectors(&self, _n: u64) {}
        pub fn job_submitted(&self, _bytes: usize) {}
        pub fn job_start(&self) {}
        pub fn job_end(&self, _nanos: u64) {}
        pub fn job_emitted(&self, _bytes: usize) {}
        pub fn ready(&self, _n: u64) {}
        pub fn lag(&self, _n: u64) {}
        pub fn init_workers(&self, _n: usize) {}
        pub fn worker_sent(&self, _index: usize) {}
        pub fn worker_started(&self, _index: usize) {}
        pub fn worker_cancelled(&self, _index: usize) {}
        pub fn read_wait(&self, _d: Duration) {}
        pub fn write_out(&self, _d: Duration) {}
        pub fn wait_window(&self, _d: Duration) {}
        pub fn wait_finalize(&self, _d: Duration) {}
        pub fn report(&self) {}
        pub fn stop(&self) {}
    }
}

/// Sector size UDIF counts in. Fixed by the format.
const SECTOR: usize = 512;

/// UDIF checksum type code for CRC-32 (`kUDIFChecksumCRC32`).
const CHECKSUM_TYPE_CRC32: u32 = 2;
/// UDIF checksum type code for MD5 (`kUDIFChecksumMD5`), as `hdiutil`
/// writes in UFBI images.
const CHECKSUM_TYPE_MD5: u32 = 4;

/// Koly `flags` bit 0: the image is "flattened" (data + resource fork in
/// one file). Every `hdiutil` UDIF has it set.
const KOLY_FLAG_FLATTENED: u32 = 1;
/// Koly `image_variant` `hdiutil` writes for a whole-device image.
const KOLY_IMAGE_VARIANT_DEVICE: u32 = 2;
/// Koly `image_variant` `hdiutil` writes for a partitioned image.
const KOLY_IMAGE_VARIANT_PARTITIONED: u32 = 1;
/// Mish `block_descriptor` value `hdiutil` uses for a whole-disk entry.
const BLKX_DESCRIPTOR_WHOLE_DISK: i32 = -2;
/// Default chunk span: 2048 sectors (1 MiB), `hdiutil`'s own.
const DEFAULT_CHUNK_SECTORS: u32 = 2048;
/// Upper bound on [`UdifWriteOptions::chunk_sectors`]. Bounds the
/// writer's per-chunk buffers (8 MiB of plaintext) while staying far below
/// the reader's own cap.
pub const MAX_WRITE_CHUNK_SECTORS: u32 = 16_384;

/// Most worker threads [`UdifWriteOptions::threads`] accepts.
pub const MAX_WRITE_THREADS: usize = 16;

/// Read-ahead block used when streaming a source into the UDIF writer.
const READ_AHEAD: usize = 8 << 20;
/// Longest zero / ignore run one descriptor carries. Kept well inside the
/// reader's [`MAX_CHUNK_SECTORS`] so a writer-produced image always
/// re-opens.
const MAX_ZERO_RUN_SECTORS: u64 = 1 << 20;
/// Longest zero run folded into a neighbouring data chunk instead of
/// getting its own `blkx` entry. Fragmented images otherwise turn every
/// small hole into a tiny compression job and an extra ordering boundary.
const ZERO_COALESCE_SECTORS: u64 = 128; // 64 KiB
const _: () = assert!(MAX_ZERO_RUN_SECTORS <= MAX_CHUNK_SECTORS);
const _: () = assert!(MAX_WRITE_CHUNK_SECTORS as u64 <= MAX_CHUNK_SECTORS);
/// Most `blkx` entries a [`UdifLayout::Map`] may have. GPT tops out
/// around 2 × 128 + a handful; this only bounds the plist.
pub const MAX_MAP_ENTRIES: usize = 4096;

/// The `plst` resource `hdiutil` adds to every UDIF image: 1032 bytes,
/// all zero but for two big-endian 1s at offset 516 (the same in every
/// image it writes, whatever the format or layout).
const PLST_LEN: usize = 1032;
const PLST_ONES_AT: usize = 516;

/// Image format, named by its `hdiutil -format` code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum UdifFormat {
    /// `UDRO` — read-only, uncompressed (raw chunks).
    Udro,
    /// `UDCO` — ADC-compressed. Always available with `dmg-write`.
    Udco,
    /// `UDZO` — zlib-compressed. Needs `dmg-write-zlib`.
    #[default]
    Udzo,
    /// `UDBZ` — bzip2-compressed. Needs `dmg-write-bzip2`.
    Udbz,
    /// `ULFO` — LZFSE-compressed. Recognised but **not yet writable**:
    /// the `compcol` LZFSE codec fstool uses can only decode. The
    /// `dmg-write-lzfse` feature reserves the slot for its encoder.
    Ulfo,
    /// `ULMO` — LZMA-compressed (each chunk an XZ stream, as current
    /// `hdiutil` writes). Needs `dmg-write-lzma`.
    Ulmo,
    /// `UFBI` — "entire device": every sector stored raw (zero sectors
    /// included) with MD5 checksums. With the default
    /// [`UdifChecksum::Crc32`] the writer records MD5, as UFBI requires;
    /// [`UdifChecksum::None`] is honoured.
    Ufbi,
    /// `UDRW` — read/write. Current `hdiutil` writes it as the bare
    /// sector image with no UDIF trailer or plist, so that is what the
    /// writer emits: the sectors, verbatim. [`UdifWriteOptions::layout`],
    /// `checksum` and `zero_runs` do not apply.
    Udrw,
}

impl UdifFormat {
    /// The `hdiutil -format` code (`"UDZO"`, …).
    pub fn name(self) -> &'static str {
        match self {
            Self::Udro => "UDRO",
            Self::Udco => "UDCO",
            Self::Udzo => "UDZO",
            Self::Udbz => "UDBZ",
            Self::Ulfo => "ULFO",
            Self::Ulmo => "ULMO",
            Self::Ufbi => "UFBI",
            Self::Udrw => "UDRW",
        }
    }

    /// Parse an `hdiutil -format` code, case-insensitively.
    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s.to_ascii_uppercase().as_str() {
            "UDRO" => Self::Udro,
            "UDCO" => Self::Udco,
            "UDZO" => Self::Udzo,
            "UDBZ" => Self::Udbz,
            "ULFO" => Self::Ulfo,
            "ULMO" => Self::Ulmo,
            "UFBI" => Self::Ufbi,
            "UDRW" => Self::Udrw,
            _ => return None,
        })
    }

    /// Whether this build can write the format (its codec feature is on).
    pub fn writable(self) -> bool {
        self.check_writable().is_ok()
    }

    fn check_writable(self) -> Result<()> {
        let missing = |feature: &str| {
            Err(crate::Error::Unsupported(format!(
                "dmg: writing {} needs the `{feature}` Cargo feature",
                self.name()
            )))
        };
        match self {
            Self::Udro | Self::Udco | Self::Ufbi | Self::Udrw => Ok(()),
            Self::Udzo if cfg!(feature = "dmg-write-zlib") => Ok(()),
            Self::Udzo => missing("dmg-write-zlib"),
            Self::Udbz if cfg!(feature = "dmg-write-bzip2") => Ok(()),
            Self::Udbz => missing("dmg-write-bzip2"),
            Self::Ulmo if cfg!(feature = "dmg-write-lzma") => Ok(()),
            Self::Ulmo => missing("dmg-write-lzma"),
            Self::Ulfo if cfg!(feature = "dmg-write-lzfse") => Ok(()),
            Self::Ulfo => missing("dmg-write-lzfse"),
        }
    }

    /// Valid range for [`UdifWriteOptions::level`], or `None` for formats
    /// without a level.
    fn level_range(self) -> Option<core::ops::RangeInclusive<u8>> {
        match self {
            Self::Udzo | Self::Udbz => Some(1..=9),
            Self::Ulmo => Some(0..=9),
            Self::Udro | Self::Udco | Self::Ulfo | Self::Ufbi | Self::Udrw => None,
        }
    }

    /// Whether all-zero sectors become zero-fill / ignore entries. UFBI
    /// stores every sector.
    fn elides_zeros(self) -> bool {
        self != Self::Ufbi
    }

    /// Whether the writer runs a compression codec for this format.
    fn compresses(self) -> bool {
        matches!(
            self,
            Self::Udco | Self::Udzo | Self::Udbz | Self::Ulmo | Self::Ulfo
        )
    }

    /// The mish `buffers_needed` field of an entry holding compressed
    /// chunks: the scratch buffer, in sectors, a reader must allocate to
    /// decode any chunk. (An entry with only raw / zero / ignore chunks
    /// gets 0, as `hdiutil` writes.)
    ///
    /// `hdiutil` writes `chunk + 8` for UDZO and `chunk + 1` for the other
    /// compressed formats — but Apple's engine apparently decodes some
    /// codecs (seen with ULMO) in place, with the compressed bytes parked
    /// at the end of that buffer, so a chunk whose
    /// `sectors + ceil(compressed / 512)` exceeds the field is rejected as
    /// corrupt. `max_in_place` is that sum over the entry's compressed
    /// chunks; the field is never smaller.
    fn buffers_needed(self, chunk_sectors: u32, max_in_place: u64) -> u32 {
        let hdiutil = match self {
            Self::Udzo => u64::from(chunk_sectors) + 8,
            _ => u64::from(chunk_sectors) + 1,
        };
        // chunk_sectors ≤ MAX_WRITE_CHUNK_SECTORS and a compressed chunk is
        // stored only when smaller than its plaintext, so this fits.
        u32::try_from(hdiutil.max(max_in_place)).unwrap_or(u32::MAX)
    }
}

/// How runs of all-zero sectors are recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum ZeroRunEncoding {
    /// Zero-fill entries (`0x00000000`); the zeros count towards the
    /// partition checksum. What `hdiutil create` writes for zero sectors.
    #[default]
    ZeroFill,
    /// "Ignore" / free-space entries (`0x00000002`); excluded from the
    /// partition checksum. What `hdiutil convert` writes for space the
    /// filesystem marks free. Reads back as zeros either way.
    Ignore,
}

/// Which checksums the writer records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum UdifChecksum {
    /// No checksums (type 0). `hdiutil verify` then has nothing to check.
    None,
    /// CRC-32 (type 2) partition, data-fork and master checksums.
    #[default]
    Crc32,
    /// MD5 (type 4, 128 bits) partition, data-fork and master checksums —
    /// what `hdiutil` records in UFBI images. Accepted by `hdiutil verify`
    /// for every format.
    ///
    /// With MD5, all-zero runs are always recorded as "ignore" entries
    /// (whatever [`UdifWriteOptions::zero_runs`] says): `hdiutil verify`
    /// hashes a zero-fill entry under MD5 as `count × 512 + 3` zero bytes,
    /// so no correct checksum over zero-fill entries would verify.
    Md5,
}

/// One `blkx` entry of a partition-oriented [`UdifLayout::Map`].
///
/// Construct with [`UdifMapEntry::new`] and assign the other fields, or
/// get a whole map from [`udif_partition_map`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UdifMapEntry {
    /// `Name` / `CFName`, e.g. `disk image (Apple_HFS : 4)`. Informational.
    pub name: String,
    /// First sector of the region.
    pub start_sector: u64,
    /// Sectors in the region; must be non-zero.
    pub sector_count: u64,
    /// The plist `ID`. `hdiutil` numbers regions `-1, 0, 1, …`.
    pub id: i32,
    /// The mish `block_descriptor`. `hdiutil` uses the region index (and
    /// `-1` for an APM driver descriptor map).
    pub descriptor: i32,
    /// Free space (`Apple_Free`): all-zero runs inside are recorded as
    /// "ignore" entries whatever [`UdifWriteOptions::zero_runs`] says, as
    /// `hdiutil` does. Non-zero sectors are still stored.
    pub free_space: bool,
}

impl UdifMapEntry {
    /// A region of `sector_count` sectors at `start_sector`, `ID` and
    /// descriptor 0, not free space.
    pub fn new(name: impl Into<String>, start_sector: u64, sector_count: u64) -> Self {
        Self {
            name: name.into(),
            start_sector,
            sector_count,
            id: 0,
            descriptor: 0,
            free_space: false,
        }
    }
}

/// How the device is split into `blkx` entries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum UdifLayout {
    /// One entry for the whole device, named
    /// [`UdifWriteOptions::partition_name`] (`hdiutil -layout NONE`).
    #[default]
    WholeDevice,
    /// Partition-oriented when the source has a GPT / APM / MBR, whole
    /// device otherwise, using [`udif_partition_map`]. Only
    /// [`write_udif`] can resolve it (it needs a [`BlockDevice`] to
    /// probe); [`UdifWriter::new`] and [`write_udif_from_reader`] refuse
    /// it with [`crate::Error::InvalidArgument`].
    Auto,
    /// Explicit entries. They must tile the device: sorted, contiguous,
    /// starting at sector 0, each non-empty, at most
    /// [`MAX_MAP_ENTRIES`]. The image must then be exactly as long as the
    /// map — more sectors are refused as they arrive, fewer at
    /// [`UdifWriter::finish`].
    Map(Vec<UdifMapEntry>),
}

/// Options for [`UdifWriter`]. Construct with `Default` and assign fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UdifWriteOptions {
    /// Image format. Default [`UdifFormat::Udzo`], which needs the
    /// `dmg-write-zlib` feature; a slimmer build must pick UDRO, UDCO,
    /// UFBI or UDRW.
    pub format: UdifFormat,
    /// Codec level: zlib and bzip2 `1..=9` (bzip2's is the block size in
    /// 100 kB units), LZMA/XZ `0..=9`. `None` uses the codec's default (6).
    /// Must be `None` for the formats without a codec level.
    pub level: Option<u8>,
    /// Maximum sectors per data chunk, `1..=`[`MAX_WRITE_CHUNK_SECTORS`].
    /// Default 2048 (1 MiB), as `hdiutil`. Sets the writer's buffer size.
    pub chunk_sectors: u32,
    /// Compression worker threads for a compressed format. `1` (the
    /// default) compresses on the caller's thread; `0` uses the host's
    /// available parallelism; larger values start a bounded worker pool.
    /// The output is byte-identical to the sequential writer.
    pub threads: usize,
    /// How all-zero sector runs are recorded. Default
    /// [`ZeroRunEncoding::ZeroFill`].
    pub zero_runs: ZeroRunEncoding,
    /// Checksums to record. Default [`UdifChecksum::Crc32`] (MD5 for
    /// UFBI).
    pub checksum: UdifChecksum,
    /// `Name` / `CFName` of the whole-device `blkx` entry. Default
    /// `whole disk (Apple_HFS : 0)`, what `hdiutil` writes for an
    /// unpartitioned HFS+ volume; the parenthesised hint is informational.
    /// Unused with a [`UdifLayout::Map`].
    pub partition_name: String,
    /// The 16-byte segment identifier in the trailer. `None` draws a
    /// random (v4 UUID) one; set it for reproducible output.
    pub segment_id: Option<[u8; 16]>,
    /// How the device is split into `blkx` entries. Default
    /// [`UdifLayout::WholeDevice`].
    pub layout: UdifLayout,
    /// Further resources for the plist beside `blkx` — a licence
    /// agreement (`LPic`, `TEXT`, `STR#`, …), carried-over resources of a
    /// converted image. Must not contain `blkx`. A `plst` here replaces
    /// the constant one `hdiutil` writes. Default none. Ignored for UDRW.
    pub resources: super::UdifResources,
}

impl Default for UdifWriteOptions {
    fn default() -> Self {
        Self {
            format: UdifFormat::default(),
            level: None,
            chunk_sectors: DEFAULT_CHUNK_SECTORS,
            threads: 1,
            zero_runs: ZeroRunEncoding::default(),
            checksum: UdifChecksum::default(),
            partition_name: "whole disk (Apple_HFS : 0)".into(),
            segment_id: None,
            layout: UdifLayout::default(),
            resources: super::UdifResources::default(),
        }
    }
}

fn check_name(what: &str, name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(crate::Error::InvalidArgument(format!(
            "dmg: {what} must not be empty"
        )));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(crate::Error::InvalidArgument(format!(
            "dmg: {what} must not contain control characters"
        )));
    }
    Ok(())
}

impl UdifWriteOptions {
    /// Check the options against this build and the format's limits,
    /// without writing anything. [`UdifWriter::new`] runs the same check.
    pub fn validate(&self) -> Result<()> {
        self.format.check_writable()?;
        if self.chunk_sectors == 0 || self.chunk_sectors > MAX_WRITE_CHUNK_SECTORS {
            return Err(crate::Error::InvalidArgument(format!(
                "dmg: chunk_sectors must be 1..={MAX_WRITE_CHUNK_SECTORS} (got {})",
                self.chunk_sectors
            )));
        }
        if self.threads > MAX_WRITE_THREADS {
            return Err(crate::Error::InvalidArgument(format!(
                "dmg: threads must be 0..={MAX_WRITE_THREADS} (got {})",
                self.threads
            )));
        }
        match (self.level, self.format.level_range()) {
            (None, _) => {}
            (Some(l), Some(r)) if r.contains(&l) => {}
            (Some(l), Some(r)) => {
                return Err(crate::Error::InvalidArgument(format!(
                    "dmg: {} level must be {}..={} (got {l})",
                    self.format.name(),
                    r.start(),
                    r.end()
                )));
            }
            (Some(_), None) => {
                return Err(crate::Error::InvalidArgument(format!(
                    "dmg: {} has no compression level",
                    self.format.name()
                )));
            }
        }
        check_name("partition_name", &self.partition_name)?;
        if let UdifLayout::Map(map) = &self.layout {
            check_map(map)?;
        }
        for r in &self.resources.entries {
            super::resources::check_kind(&r.kind)?;
            if r.kind == super::BLKX_RESOURCE {
                return Err(crate::Error::InvalidArgument(
                    "dmg: UdifWriteOptions::resources must not contain blkx — the writer \
                     builds the chunk tables itself"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    /// The checksum actually recorded: UFBI upgrades CRC-32 to MD5, UDRW
    /// records none.
    fn effective_checksum(&self) -> UdifChecksum {
        match (self.format, self.checksum) {
            (UdifFormat::Udrw, _) => UdifChecksum::None,
            (UdifFormat::Ufbi, UdifChecksum::Crc32) => UdifChecksum::Md5,
            (_, c) => c,
        }
    }
}

/// Check that `map` tiles `[0, end)`; returns `end`.
fn check_map(map: &[UdifMapEntry]) -> Result<u64> {
    if map.is_empty() || map.len() > MAX_MAP_ENTRIES {
        return Err(crate::Error::InvalidArgument(format!(
            "dmg: a layout map needs 1..={MAX_MAP_ENTRIES} entries (got {})",
            map.len()
        )));
    }
    let mut next = 0u64;
    for (i, e) in map.iter().enumerate() {
        check_name("layout map entry name", &e.name)?;
        if e.sector_count == 0 {
            return Err(crate::Error::InvalidArgument(format!(
                "dmg: layout map entry {i} ({:?}) is empty",
                e.name
            )));
        }
        if e.start_sector != next {
            return Err(crate::Error::InvalidArgument(format!(
                "dmg: layout map entry {i} ({:?}) starts at sector {}, expected {next} \
                 (entries must be sorted and contiguous from sector 0)",
                e.name, e.start_sector
            )));
        }
        next = next.checked_add(e.sector_count).ok_or_else(|| {
            crate::Error::InvalidArgument("dmg: layout map overflows u64 sectors".into())
        })?;
    }
    Ok(next)
}

/// What [`UdifWriter::finish`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UdifSummary {
    /// Virtual size in 512-byte sectors.
    pub sector_count: u64,
    /// Bytes of chunk payload in the data fork (for UDRW: the sectors).
    pub data_fork_length: u64,
    /// Bytes of the XML plist (0 for UDRW).
    pub plist_length: u64,
    /// Total bytes written to the sink (data fork + plist + trailer).
    pub bytes_written: u64,
    /// Chunk descriptors in the mish tables (excluding terminators).
    pub chunk_count: usize,
    /// The single partition (blkx) CRC-32 of a whole-device CRC-32 image;
    /// `None` otherwise (a partitioned image has one per entry, folded
    /// into [`master_crc32`](Self::master_crc32)).
    pub partition_crc32: Option<u32>,
    /// Data-fork CRC-32, when CRC-32 checksums were recorded.
    pub data_fork_crc32: Option<u32>,
    /// Master CRC-32, when CRC-32 checksums were recorded.
    pub master_crc32: Option<u32>,
    /// `blkx` entries written (0 for UDRW).
    pub blkx_count: usize,
    /// The checksum kind actually recorded.
    pub checksum: UdifChecksum,
    /// Data-fork MD5, when MD5 checksums were recorded.
    pub data_fork_md5: Option<[u8; 16]>,
    /// Master MD5, when MD5 checksums were recorded.
    pub master_md5: Option<[u8; 16]>,
}

/// Running checksum of one kind.
enum Digest {
    None,
    Crc32(u32),
    Md5(Box<Md5>),
}

/// A finished checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sum {
    None,
    Crc32(u32),
    Md5([u8; 16]),
}

impl Digest {
    fn new(kind: UdifChecksum) -> Self {
        match kind {
            UdifChecksum::None => Self::None,
            UdifChecksum::Crc32 => Self::Crc32(0),
            UdifChecksum::Md5 => Self::Md5(Box::new(Md5::new())),
        }
    }

    fn update(&mut self, b: &[u8]) {
        match self {
            Self::None => {}
            Self::Crc32(c) => *c = crate::crc::crc32_append(*c, b),
            Self::Md5(m) => m.update(b),
        }
    }

    fn finish(self) -> Sum {
        match self {
            Self::None => Sum::None,
            Self::Crc32(c) => Sum::Crc32(c),
            Self::Md5(m) => Sum::Md5(m.finish()),
        }
    }
}

impl Sum {
    fn type_code(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Crc32(_) => CHECKSUM_TYPE_CRC32,
            Self::Md5(_) => CHECKSUM_TYPE_MD5,
        }
    }

    fn bits(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Crc32(_) => 32,
            Self::Md5(_) => 128,
        }
    }

    /// The UDIFChecksum `data[32]` words as stored (big-endian CRC, raw
    /// digest), zero-padded to 128 bytes.
    fn bytes(self) -> [u8; 128] {
        let mut b = [0u8; 128];
        match self {
            Self::None => {}
            Self::Crc32(c) => b[..4].copy_from_slice(&c.to_be_bytes()),
            Self::Md5(d) => b[..16].copy_from_slice(&d),
        }
        b
    }

    /// The bytes the master checksum covers for this partition checksum.
    fn raw(self) -> Vec<u8> {
        match self {
            Self::None => Vec::new(),
            Self::Crc32(c) => c.to_be_bytes().to_vec(),
            Self::Md5(d) => d.to_vec(),
        }
    }

    fn crc32(self) -> Option<u32> {
        match self {
            Self::Crc32(c) => Some(c),
            _ => None,
        }
    }

    fn md5(self) -> Option<[u8; 16]> {
        match self {
            Self::Md5(d) => Some(d),
            _ => None,
        }
    }
}

/// One descriptor queued for the mish table. `sector` is absolute; it
/// is made relative to the entry's start when encoded.
#[derive(Debug, Clone, Copy)]
struct Entry {
    kind: ChunkType,
    sector: u64,
    count: u64,
    offset: u64,
    length: u64,
}

/// A resolved `blkx` region. `count` is `None` for the open-ended
/// whole-device entry.
#[derive(Debug, Clone)]
struct Region {
    name: String,
    start: u64,
    count: Option<u64>,
    id: i32,
    descriptor: i32,
    free: bool,
}

/// A finished `blkx` entry, ready for the plist.
struct Blkx {
    name: String,
    id: i32,
    mish: Vec<u8>,
    sum: Sum,
}

/// One chunk handed to a compression worker.
struct ChunkJob {
    index: u64,
    plain: Vec<u8>,
}

/// A worker's result for one chunk.
struct ChunkDone {
    index: u64,
    /// `None` for formats that store raw (UDRO/UFBI).
    encoded: Option<(ChunkType, Vec<u8>)>,
    /// The original plaintext, returned for buffer reuse.
    plain: Vec<u8>,
}

/// Metadata kept by the main thread for each dispatched chunk.
#[derive(Clone, Copy)]
struct ChunkMeta {
    sector: u64,
    count: u64,
}

/// An item in the ordered output sequence: a compressed/raw data chunk or a
/// zero/ignore run. Zero entries have no payload and get their data-fork
/// offset when published, so they never force a compression drain.
#[derive(Clone, Copy)]
enum Meta {
    Data(ChunkMeta),
    Zero {
        kind: ChunkType,
        sector: u64,
        count: u64,
    },
}

/// Turn a caught worker panic into an error the coordinator can propagate.
fn worker_panic_error(payload: Box<dyn std::any::Any + Send>) -> crate::Error {
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("unknown panic");
    crate::Error::Io(std::io::Error::other(format!(
        "dmg: compression worker panicked: {message}"
    )))
}

/// Clone a stats handle. The no-op stats type is `Copy`, while the
/// `udif-stats` build's handle owns an `Arc`; this keeps both builds happy
/// without a feature-dependent `clone_on_copy` lint.
#[allow(clippy::clone_on_copy)]
fn clone_stats(stats: &udif_stats::Stats) -> udif_stats::Stats {
    stats.clone()
}

/// A bounded compression worker pool. Only `encode_chunk` runs in the
/// workers; sector scanning, zero-run handling, checksums, ordering and
/// output all stay on the main thread, so parallel output is byte-identical
/// to the sequential writer.
struct Parallel {
    senders: Vec<Sender<ChunkJob>>,
    next_sender: usize,
    rx: Receiver<crate::Result<ChunkDone>>,
    workers: Vec<JoinHandle<()>>,
    /// Chunks dispatched but not yet written.
    window: usize,
    in_flight: usize,
    next_send: u64,
    next_write: u64,
    ready: BTreeMap<u64, ChunkDone>,
    meta: VecDeque<Meta>,
    free: Vec<Vec<u8>>,
    chunk_bytes: usize,
}

impl Parallel {
    fn new(
        format: UdifFormat,
        level: Option<u8>,
        threads: usize,
        chunk_bytes: usize,
        stats: udif_stats::Stats,
    ) -> Result<Self> {
        let threads = threads.clamp(1, MAX_WRITE_THREADS);
        stats.init_workers(threads);
        let (tx, rx) = mpsc::channel();
        let mut senders = Vec::with_capacity(threads);
        let mut workers = Vec::with_capacity(threads);
        for index in 0..threads {
            let (job_tx, job_rx) = mpsc::channel::<ChunkJob>();
            let tx = tx.clone();
            // A separate sender survives the catch_unwind so a panicking
            // worker always reports a result: without it the coordinator can
            // block in `rx.recv` forever while the surviving workers hold
            // their own result senders open.
            let fail_tx = tx.clone();
            let worker_stats = clone_stats(&stats);
            let worker = std::thread::Builder::new()
                .name("fstool-udif".into())
                .spawn(move || {
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        while let Ok(job) = job_rx.recv() {
                            worker_stats.worker_started(index);
                            worker_stats.job_start();
                            let t = std::time::Instant::now();
                            let result =
                                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    encode_chunk(format, level, &job.plain)
                                })) {
                                    Ok(result) => result.map(|encoded| ChunkDone {
                                        index: job.index,
                                        encoded,
                                        plain: job.plain,
                                    }),
                                    Err(payload) => Err(worker_panic_error(payload)),
                                };
                            worker_stats.job_end(t.elapsed().as_nanos() as u64);
                            if tx.send(result).is_err() {
                                break;
                            }
                        }
                    }));
                    if let Err(payload) = outcome {
                        let _ = fail_tx.send(Err(worker_panic_error(payload)));
                    }
                })
                .map_err(|e| {
                    crate::Error::Io(std::io::Error::other(format!(
                        "dmg: cannot start compression worker: {e}"
                    )))
                })?;
            senders.push(job_tx);
            workers.push(worker);
        }
        Ok(Self {
            senders,
            next_sender: 0,
            rx,
            workers,
            // Bounded in-flight chunks. Larger windows did not change
            // throughput in testing, so keep the memory bounded.
            // Bounded in-flight chunks. With the published-progress
            // counter, deeper windows did not improve completed
            // throughput; they only buffered producer read-ahead.
            window: (threads * 4).max(2),
            in_flight: 0,
            next_send: 0,
            next_write: 0,
            ready: BTreeMap::new(),
            meta: VecDeque::new(),
            free: Vec::new(),
            chunk_bytes,
        })
    }

    fn take_buffer(&mut self) -> Vec<u8> {
        self.free
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(self.chunk_bytes))
    }

    fn recycle(&mut self, mut buf: Vec<u8>) {
        if buf.capacity() >= self.chunk_bytes {
            buf.clear();
            self.free.push(buf);
        }
    }
}

impl Drop for Parallel {
    fn drop(&mut self) {
        self.senders.clear();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

/// Streaming UDIF encoder over a caller-owned sink.
///
/// Feed sectors with [`write_sectors`](Self::write_sectors), then call
/// [`finish`](Self::finish) to emit the plist and trailer and get the
/// sink back.
///
/// Memory is bounded by the in-flight window, not by a single fixed total.
/// With `T` workers the pool keeps up to `4 × T` data jobs in flight; each
/// holds up to one chunk of plaintext and, until published, an encoded copy.
/// Add one pending chunk, an 8 MiB read-ahead buffer, recycled buffers, and
/// the per-chunk descriptors. At the defaults (3 workers, 1 MiB chunks) this
/// is tens of MiB; at the supported maximum (16 workers, 8 MiB chunks) it can
/// exceed 1 GiB. Descriptors (about 40 bytes each) and plist resources grow
/// with chunk count and image fragmentation, so no single total is fixed.
///
/// Errors from the sink or a codec are returned as they happen; after
/// one, the writer is poisoned and every later call fails, so a
/// half-written image is never finished into something that looks
/// valid. (A call rejected up front — a length that isn't whole
/// sectors, or more sectors than a layout map covers — writes nothing
/// and does not poison.) Dropping an unfinished writer leaves the sink
/// holding an incomplete image with no trailer — discard it.
pub struct UdifWriter<W: Write + Seek> {
    out: W,
    opts: UdifWriteOptions,
    checksum: UdifChecksum,
    /// Absolute sink position where the data fork starts.
    base: u64,
    /// Bytes of data fork written so far.
    fork_len: u64,
    /// Sectors accepted so far.
    sectors: u64,
    /// Plaintext of the data run being accumulated (< one chunk).
    pending: Vec<u8>,
    /// First sector of `pending`.
    pending_start: u64,
    /// Open zero run: (first sector, count).
    zero_run: Option<(u64, u64)>,
    /// The `blkx` regions, and the index of the one being filled.
    regions: Vec<Region>,
    region: usize,
    /// End of the last region, when the layout is a fixed map.
    map_end: Option<u64>,
    /// Descriptors of the current region.
    entries: Vec<Entry>,
    /// Finished regions.
    done: Vec<Blkx>,
    chunk_count: usize,
    part_sum: Digest,
    fork_sum: Digest,
    poisoned: bool,
    /// Worker pool for compressed chunks; `None` = sequential.
    parallel: Option<Parallel>,
    /// Opt-in pipeline counters; no-ops unless built with `udif-stats`.
    stats: udif_stats::Stats,
}

impl<W: Write + Seek> std::fmt::Debug for UdifWriter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdifWriter")
            .field("format", &self.opts.format)
            .field("base", &self.base)
            .field("sectors", &self.sectors)
            .field("fork_len", &self.fork_len)
            .field("region", &self.region)
            .field("chunks", &(self.chunk_count + self.entries.len()))
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl<W: Write + Seek> UdifWriter<W> {
    /// Validate `opts` and start an image at the sink's current position
    /// (normally 0; the trailer records it as the data-fork offset).
    ///
    /// [`UdifLayout::Auto`] is refused here — resolve it first with
    /// [`udif_partition_map`], or use [`write_udif`].
    pub fn new(mut out: W, opts: &UdifWriteOptions) -> Result<Self> {
        opts.validate()?;
        // UDRW is the bare sectors: no blkx entries to lay out.
        let layout = if opts.format == UdifFormat::Udrw {
            &UdifLayout::WholeDevice
        } else {
            &opts.layout
        };
        let (regions, map_end) = match layout {
            UdifLayout::WholeDevice => (
                vec![Region {
                    name: opts.partition_name.clone(),
                    start: 0,
                    count: None,
                    id: 0,
                    descriptor: BLKX_DESCRIPTOR_WHOLE_DISK,
                    free: false,
                }],
                None,
            ),
            UdifLayout::Map(map) => (
                map.iter()
                    .map(|e| Region {
                        name: e.name.clone(),
                        start: e.start_sector,
                        count: Some(e.sector_count),
                        id: e.id,
                        descriptor: e.descriptor,
                        free: e.free_space,
                    })
                    .collect(),
                Some(check_map(map)?),
            ),
            UdifLayout::Auto => {
                return Err(crate::Error::InvalidArgument(
                    "dmg: UdifLayout::Auto needs a BlockDevice to probe — use write_udif, \
                     or build the map with udif_partition_map"
                        .into(),
                ));
            }
        };
        let base = out.stream_position()?;
        let checksum = opts.effective_checksum();
        let chunk_bytes = if opts.format == UdifFormat::Udrw {
            0
        } else {
            opts.chunk_sectors as usize * SECTOR
        };
        let threads = if opts.threads == 0 {
            std::thread::available_parallelism().map_or(1, |n| n.get())
        } else {
            opts.threads
        };
        let stats = udif_stats::Stats::from_env();
        let parallel = if threads > 1 && opts.format.compresses() {
            Some(Parallel::new(
                opts.format,
                opts.level,
                threads,
                chunk_bytes,
                clone_stats(&stats),
            )?)
        } else {
            None
        };
        Ok(Self {
            out,
            opts: opts.clone(),
            checksum,
            base,
            fork_len: 0,
            sectors: 0,
            pending: Vec::with_capacity(chunk_bytes),
            pending_start: 0,
            zero_run: None,
            regions,
            region: 0,
            map_end,
            entries: Vec::new(),
            done: Vec::new(),
            chunk_count: 0,
            part_sum: Digest::new(checksum),
            fork_sum: Digest::new(checksum),
            poisoned: false,
            parallel,
            stats,
        })
    }

    /// Sectors accepted so far.
    pub fn sectors_written(&self) -> u64 {
        self.sectors
    }

    /// Handle for the optional `udif-stats` counters.
    pub(crate) fn stats_handle(&self) -> udif_stats::Stats {
        clone_stats(&self.stats)
    }

    /// Append whole sectors. `data.len()` must be a multiple of 512, and
    /// with a [`UdifLayout::Map`] the total must stay within the map.
    pub fn write_sectors(&mut self, data: &[u8]) -> Result<()> {
        self.check_live()?;
        if !data.len().is_multiple_of(SECTOR) {
            return Err(crate::Error::InvalidArgument(format!(
                "dmg: write_sectors needs whole 512-byte sectors (got {} bytes)",
                data.len()
            )));
        }
        let n = (data.len() / SECTOR) as u64;
        let total = self.sectors.checked_add(n).ok_or_else(|| {
            crate::Error::InvalidArgument("dmg: sector count overflows u64".into())
        })?;
        if let Some(end) = self.map_end
            && total > end
        {
            return Err(crate::Error::InvalidArgument(format!(
                "dmg: {total} sectors exceed the {end}-sector layout map"
            )));
        }
        let r = self.write_sectors_inner(data);
        self.poison_on_err(r)
    }

    /// Flush the last chunk, write the plist and koly trailer, flush the
    /// sink, and return it with a summary. Nothing is renamed, synced to
    /// disk or published — that remains the caller's job.
    pub fn finish(mut self) -> Result<(W, UdifSummary)> {
        self.check_live()?;
        let r = self.finish_inner();
        let summary = self.poison_on_err(r)?;
        Ok((self.out, summary))
    }

    fn check_live(&self) -> Result<()> {
        if self.poisoned {
            return Err(crate::Error::InvalidArgument(
                "dmg: UDIF writer already failed; the image is incomplete".into(),
            ));
        }
        Ok(())
    }

    fn poison_on_err<T>(&mut self, r: Result<T>) -> Result<T> {
        if r.is_err() {
            self.poisoned = true;
        }
        r
    }

    /// End sector of the region being filled, if it is bounded.
    fn region_end(&self) -> Option<u64> {
        let r = &self.regions[self.region];
        r.count.map(|c| r.start + c)
    }

    fn write_sectors_inner(&mut self, data: &[u8]) -> Result<()> {
        if self.opts.format == UdifFormat::Udrw {
            self.out.write_all(data)?;
            self.fork_len += data.len() as u64;
            self.sectors += (data.len() / SECTOR) as u64;
            return Ok(());
        }
        let chunk_bytes = self.opts.chunk_sectors as usize * SECTOR;
        let elide = self.opts.format.elides_zeros();
        let mut zero_n = 0u64;
        let mut data_n = 0u64;
        for sector in data.as_chunks::<SECTOR>().0 {
            let lba = self.sectors;
            if self.region_end() == Some(lba) {
                self.close_region()?;
            }
            if elide && is_zero(sector) {
                zero_n += 1;
                // Entering a zero run does not flush a partial data chunk:
                // a short run is folded into that chunk when it closes.
                // Only runs that are certainly too long to fold get their
                // preceding data flushed promptly so a worker can start.
                let coalesce = self.opts.format.compresses() && self.zero_kind() == ChunkType::Zero;
                let count = self.zero_run.map(|(_, n)| n).unwrap_or(0);
                if count == 0 {
                    self.zero_run = Some((lba, 1));
                    if !coalesce {
                        self.flush_pending()?;
                    }
                } else if count < MAX_ZERO_RUN_SECTORS {
                    if let Some((_, n)) = self.zero_run.as_mut() {
                        *n += 1;
                    }
                } else {
                    // The run hit its descriptor limit; close it and begin
                    // a new run at this sector.
                    self.close_zero_run(false)?;
                    self.zero_run = Some((lba, 1));
                }
                if coalesce {
                    // Once the run no longer fits in the current chunk,
                    // it cannot be folded; release the preceding data.
                    let room = chunk_bytes.saturating_sub(self.pending.len());
                    let limit = ZERO_COALESCE_SECTORS.min((room / SECTOR) as u64);
                    if self.zero_run.map(|(_, n)| n) == Some(limit + 1) {
                        self.flush_pending()?;
                    }
                }
            } else {
                // Close any zero run first: a short run joins this data
                // chunk, a long one is emitted as its own entry.
                self.close_zero_run(true)?;
                data_n += 1;
                if self.pending.is_empty() {
                    self.pending_start = lba;
                }
                self.pending.extend_from_slice(sector);
                self.part_sum.update(sector);
                if self.pending.len() >= chunk_bytes {
                    self.flush_pending()?;
                }
            }
            self.sectors = lba + 1;
        }
        self.stats.add_source_sectors((data.len() / SECTOR) as u64);
        self.stats.add_zero_sectors(zero_n);
        self.stats.add_data_sectors(data_n);
        Ok(())
    }

    /// How a zero run in the current region is recorded.
    fn zero_kind(&self) -> ChunkType {
        if self.regions[self.region].free
            || self.opts.zero_runs == ZeroRunEncoding::Ignore
            || self.checksum == UdifChecksum::Md5
        {
            ChunkType::Ignored
        } else {
            ChunkType::Zero
        }
    }

    fn close_zero_run(&mut self, followed_by_data: bool) -> Result<()> {
        let Some((sector, count)) = self.zero_run.take() else {
            return Ok(());
        };
        let kind = self.zero_kind();
        let chunk_bytes = self.opts.chunk_sectors as usize * SECTOR;
        let run_bytes = count as usize * SECTOR;
        // A short zero run is cheaper folded into the surrounding data
        // chunk: one compression job instead of an extra tiny job and an
        // ordering boundary. Only compressed formats benefit (a raw chunk
        // would store the zeros verbatim), and only a normal `Zero` entry:
        // free regions, MD5 checksums and `Ignore` runs must stay elided.
        let coalesce = kind == ChunkType::Zero
            && self.opts.format.compresses()
            && count <= ZERO_COALESCE_SECTORS
            && (followed_by_data || !self.pending.is_empty())
            && self.pending.len() + run_bytes <= chunk_bytes;
        if coalesce {
            if self.pending.is_empty() {
                self.pending_start = sector;
            }
            let start = self.pending.len();
            self.pending.resize(start + run_bytes, 0);
            // Coalesced zeros still belong to the partition checksum.
            self.part_sum.update(&self.pending[start..]);
            if self.pending.len() >= chunk_bytes {
                self.flush_pending()?;
            }
            return Ok(());
        }
        // Data before an elided run has to reach the output first.
        self.flush_pending()?;
        if kind == ChunkType::Zero {
            // Zeros were not fed through the data path, but a zero-fill
            // run still counts toward the partition checksum.
            let zeros = [0u8; SECTOR];
            for _ in 0..count {
                self.part_sum.update(&zeros);
            }
        }
        if let Some(p) = self.parallel.as_mut() {
            // No payload: enqueue the zero entry in the ordered sequence.
            // Its data-fork offset is assigned when it is published, so
            // this must not drain compression.
            p.meta.push_back(Meta::Zero {
                kind,
                sector,
                count,
            });
            p.next_send += 1;
        } else {
            self.entries.push(Entry {
                kind,
                sector,
                count,
                offset: self.fork_len,
                length: 0,
            });
        }
        Ok(())
    }

    /// Encode and write the accumulated data run as one chunk.
    fn flush_pending(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        if self.parallel.is_some() {
            return self.flush_pending_parallel();
        }
        let count = (self.pending.len() / SECTOR) as u64;
        self.stats.job_submitted(self.pending.len());
        let encoded = encode_chunk(self.opts.format, self.opts.level, &self.pending)?;
        let (kind, payload): (ChunkType, &[u8]) = match &encoded {
            Some((kind, bytes)) if bytes.len() < self.pending.len() => (*kind, bytes),
            _ => (ChunkType::Raw, &self.pending),
        };
        let t = std::time::Instant::now();
        self.out.write_all(payload)?;
        self.stats.write_out(t.elapsed());
        self.fork_sum.update(payload);
        let length = payload.len() as u64;
        self.stats.job_emitted(length as usize);
        self.entries.push(Entry {
            kind,
            sector: self.pending_start,
            count,
            offset: self.fork_len,
            length,
        });
        self.fork_len += length;
        self.stats.add_published_sectors(count);
        self.pending.clear();
        Ok(())
    }

    /// Dispatch the accumulated run to a worker. The result is written,
    /// in dispatch order, by `drain_ready`.
    fn flush_pending_parallel(&mut self) -> Result<()> {
        let count = (self.pending.len() / SECTOR) as u64;
        let plain = std::mem::take(&mut self.pending);
        self.stats.job_submitted(plain.len());
        let mut p = self.parallel.take().expect("parallel writer state");
        let index = p.next_send;
        p.next_send += 1;
        p.in_flight += 1;
        p.meta.push_back(Meta::Data(ChunkMeta {
            sector: self.pending_start,
            count,
        }));
        let sender = p.senders[p.next_sender].clone();
        let worker_index = p.next_sender;
        p.next_sender = (p.next_sender + 1) % p.senders.len();
        self.stats.worker_sent(worker_index);
        let sent = sender.send(ChunkJob { index, plain });
        self.pending = p.take_buffer();
        if sent.is_err() {
            self.stats.worker_cancelled(worker_index);
            self.parallel = Some(p);
            return Err(crate::Error::Io(std::io::Error::other(
                "dmg: compression worker stopped",
            )));
        }
        let r = self.drain_ready(&mut p, false);
        self.parallel = Some(p);
        r
    }

    /// Wait for every dispatched chunk and write it. Used at region
    /// boundaries and finalization; zero-run items are ordinary ordered
    /// sequence entries and no longer force a drain.
    fn drain_all(&mut self) -> Result<()> {
        let Some(mut p) = self.parallel.take() else {
            return Ok(());
        };
        let r = self.drain_ready(&mut p, true);
        self.parallel = Some(p);
        r
    }

    /// Receive worker results and write every contiguous one. With
    /// `all`, block until nothing is in flight; otherwise only keep the
    /// in-flight window bounded.
    fn drain_ready(&mut self, p: &mut Parallel, all: bool) -> Result<()> {
        loop {
            match p.rx.try_recv() {
                Ok(res) => {
                    let done = res?;
                    p.ready.insert(done.index, done);
                    self.emit_ready(p)?;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if p.in_flight > 0 {
                        return Err(crate::Error::Io(std::io::Error::other(
                            "dmg: compression worker stopped",
                        )));
                    }
                    break;
                }
            }
        }
        while p.in_flight > 0 && (all || p.in_flight >= p.window) {
            let t = std::time::Instant::now();
            let res = p.rx.recv().map_err(|_| {
                crate::Error::Io(std::io::Error::other("dmg: compression worker stopped"))
            })?;
            let waited = t.elapsed();
            if all {
                self.stats.wait_finalize(waited);
            } else {
                self.stats.wait_window(waited);
            }
            let done = res?;
            p.ready.insert(done.index, done);
            self.emit_ready(p)?;
        }
        // Publish any zero-run items sitting at the head (they have no
        // worker result to wait for).
        self.emit_ready(p)?;
        Ok(())
    }

    /// Write completed chunks in dispatch order, updating the data-fork
    /// checksum and the mish descriptors exactly as the sequential path.
    fn emit_ready(&mut self, p: &mut Parallel) -> Result<()> {
        while let Some(front) = p.meta.front().copied() {
            match front {
                Meta::Zero {
                    kind,
                    sector,
                    count,
                } => {
                    p.meta.pop_front();
                    self.entries.push(Entry {
                        kind,
                        sector,
                        count,
                        offset: self.fork_len,
                        length: 0,
                    });
                    self.stats.add_published_sectors(count);
                    p.next_write += 1;
                }
                Meta::Data(_) => {
                    let Some(done) = p.ready.remove(&p.next_write) else {
                        break;
                    };
                    let meta = p.meta.pop_front().ok_or_else(|| {
                        crate::Error::InvalidArgument("dmg: chunk metadata underflow".into())
                    })?;
                    let Meta::Data(meta) = meta else {
                        unreachable!("front was checked as data");
                    };
                    let ChunkDone { encoded, plain, .. } = done;
                    let (kind, payload, recycle) = match encoded {
                        Some((kind, bytes)) if bytes.len() < plain.len() => {
                            (kind, bytes, Some(plain))
                        }
                        _ => (ChunkType::Raw, plain, None),
                    };
                    let t = std::time::Instant::now();
                    self.out.write_all(&payload)?;
                    self.stats.write_out(t.elapsed());
                    self.fork_sum.update(&payload);
                    let length = payload.len() as u64;
                    self.stats.job_emitted(length as usize);
                    self.entries.push(Entry {
                        kind,
                        sector: meta.sector,
                        count: meta.count,
                        offset: self.fork_len,
                        length,
                    });
                    self.fork_len += length;
                    self.stats.add_published_sectors(meta.count);
                    p.next_write += 1;
                    p.in_flight -= 1;
                    if let Some(buf) = recycle {
                        p.recycle(buf);
                    }
                    if kind == ChunkType::Raw {
                        p.recycle(payload);
                    }
                }
            }
        }
        self.stats.ready(p.ready.len() as u64);
        self.stats.lag(p.next_send.saturating_sub(p.next_write));
        Ok(())
    }

    /// Finish the current region's mish table and move to the next.
    fn close_region(&mut self) -> Result<()> {
        // Close the zero run first: a short trailing run may fold into the
        // pending data chunk.
        self.close_zero_run(false)?;
        self.flush_pending()?;
        // Region boundaries still wait for every item in the region so its
        // mish table and checksum are complete.
        self.drain_all()?;
        if self.entries.len() >= u32::MAX as usize {
            return Err(crate::Error::Unsupported(
                "dmg: too many chunks for one mish table; raise chunk_sectors".into(),
            ));
        }
        let region = &self.regions[self.region];
        let count = self.sectors - region.start;
        let sum = std::mem::replace(&mut self.part_sum, Digest::new(self.checksum)).finish();
        let mish = self.encode_mish(region.start, count, region.descriptor, sum);
        self.done.push(Blkx {
            name: region.name.clone(),
            id: region.id,
            mish,
            sum,
        });
        self.chunk_count += self.entries.len();
        self.entries.clear();
        self.region += 1;
        Ok(())
    }

    fn finish_inner(&mut self) -> Result<UdifSummary> {
        if self.sectors == 0 {
            return Err(crate::Error::InvalidArgument(
                "dmg: refusing to finish an empty image (no sectors written)".into(),
            ));
        }
        if self.opts.format == UdifFormat::Udrw {
            self.out.flush()?;
            self.stats.stop();
            return Ok(UdifSummary {
                sector_count: self.sectors,
                data_fork_length: self.fork_len,
                plist_length: 0,
                bytes_written: self.fork_len,
                chunk_count: 0,
                partition_crc32: None,
                data_fork_crc32: None,
                master_crc32: None,
                blkx_count: 0,
                checksum: UdifChecksum::None,
                data_fork_md5: None,
                master_md5: None,
            });
        }
        if let Some(end) = self.map_end
            && self.sectors != end
        {
            return Err(crate::Error::InvalidArgument(format!(
                "dmg: image has {} sectors but the layout map covers {end}",
                self.sectors
            )));
        }
        self.close_region()?;
        debug_assert_eq!(self.region, self.regions.len());

        let mut master = Digest::new(self.checksum);
        for b in &self.done {
            master.update(&b.sum.raw());
        }
        let master = master.finish();
        let fork = std::mem::replace(&mut self.fork_sum, Digest::None).finish();

        let plist = if self.opts.resources.entries.is_empty() {
            build_plist(&self.done)
        } else {
            build_plist_with(&self.done, &self.opts.resources)
        };
        self.out.write_all(plist.as_bytes())?;

        let data_fork_offset = self.base;
        let xml_offset = self
            .base
            .checked_add(self.fork_len)
            .ok_or_else(|| crate::Error::InvalidArgument("dmg: image too large".into()))?;
        let image_variant = match self.opts.layout {
            UdifLayout::Map(_) => KOLY_IMAGE_VARIANT_PARTITIONED,
            _ => KOLY_IMAGE_VARIANT_DEVICE,
        };
        let trailer = KolyTrailer {
            signature: KOLY_MAGIC,
            version: 4,
            header_size: KOLY_SIZE as u32,
            flags: KOLY_FLAG_FLATTENED,
            running_data_fork_offset: 0,
            data_fork_offset,
            data_fork_length: self.fork_len,
            rsrc_fork_offset: 0,
            rsrc_fork_length: 0,
            segment_number: 1,
            segment_count: 1,
            segment_id: self
                .opts
                .segment_id
                .unwrap_or_else(|| *uuid::Uuid::new_v4().as_bytes()),
            data_checksum_type: fork.type_code(),
            data_checksum_size: fork.bits(),
            data_checksum: fork.bytes(),
            xml_offset,
            xml_length: plist.len() as u64,
            master_checksum_type: master.type_code(),
            master_checksum_size: master.bits(),
            master_checksum: master.bytes(),
            image_variant,
            sector_count: self.sectors,
        };
        self.out.write_all(&trailer.encode())?;
        self.out.flush()?;

        let whole_device = matches!(self.opts.layout, UdifLayout::WholeDevice);
        self.stats.report();
        self.stats.stop();
        Ok(UdifSummary {
            sector_count: self.sectors,
            data_fork_length: self.fork_len,
            plist_length: plist.len() as u64,
            bytes_written: self.fork_len + plist.len() as u64 + KOLY_SIZE,
            chunk_count: self.chunk_count,
            partition_crc32: if whole_device {
                self.done[0].sum.crc32()
            } else {
                None
            },
            data_fork_crc32: fork.crc32(),
            master_crc32: master.crc32(),
            blkx_count: self.done.len(),
            checksum: self.checksum,
            data_fork_md5: fork.md5(),
            master_md5: master.md5(),
        })
    }

    /// Serialise the current region's BLKX table, terminator included.
    fn encode_mish(&self, first: u64, count: u64, descriptor: i32, sum: Sum) -> Vec<u8> {
        let n = self.entries.len() + 1;
        let mut b = vec![0u8; MISH_HEADER_LEN + n * CHUNK_LEN];
        b[0x000..0x004].copy_from_slice(&MISH_MAGIC.to_be_bytes());
        b[0x004..0x008].copy_from_slice(&1u32.to_be_bytes()); // version
        b[0x008..0x010].copy_from_slice(&first.to_be_bytes());
        b[0x010..0x018].copy_from_slice(&count.to_be_bytes());
        b[0x018..0x020].copy_from_slice(&0u64.to_be_bytes()); // data offset
        let compressed = |e: &&Entry| {
            !matches!(
                e.kind,
                ChunkType::Raw | ChunkType::Zero | ChunkType::Ignored
            )
        };
        let buffers = self
            .entries
            .iter()
            .filter(compressed)
            .map(|e| e.count + e.length.div_ceil(SECTOR as u64))
            .max()
            .map_or(0, |in_place| {
                self.opts
                    .format
                    .buffers_needed(self.opts.chunk_sectors, in_place)
            });
        b[0x020..0x024].copy_from_slice(&buffers.to_be_bytes());
        b[0x024..0x028].copy_from_slice(&descriptor.to_be_bytes());
        // reserved[6] stays zero; then the UDIFChecksum (type, bits, data).
        b[0x040..0x044].copy_from_slice(&sum.type_code().to_be_bytes());
        b[0x044..0x048].copy_from_slice(&sum.bits().to_be_bytes());
        b[0x048..0x0C8].copy_from_slice(&sum.bytes());
        b[0x0C8..0x0CC].copy_from_slice(&(n as u32).to_be_bytes());
        let terminator = Entry {
            kind: ChunkType::Terminator,
            sector: first + count,
            count: 0,
            offset: self.fork_len,
            length: 0,
        };
        for (i, e) in self.entries.iter().chain([&terminator]).enumerate() {
            let o = MISH_HEADER_LEN + i * CHUNK_LEN;
            b[o..o + 4].copy_from_slice(&e.kind.to_u32().to_be_bytes());
            // comment (o+4..o+8) stays zero.
            b[o + 0x08..o + 0x10].copy_from_slice(&(e.sector - first).to_be_bytes());
            b[o + 0x10..o + 0x18].copy_from_slice(&e.count.to_be_bytes());
            b[o + 0x18..o + 0x20].copy_from_slice(&e.offset.to_be_bytes());
            b[o + 0x20..o + 0x28].copy_from_slice(&e.length.to_be_bytes());
        }
        b
    }
}

fn is_zero(sector: &[u8]) -> bool {
    let (words, tail) = sector.as_chunks::<8>();
    words.iter().all(|w| u64::from_ne_bytes(*w) == 0) && tail.iter().all(|&b| b == 0)
}

/// Encode one data run with the format's codec. `None` means "store raw"
/// (UDRO, UFBI). The caller falls back to raw when the result isn't
/// smaller.
fn encode_chunk(
    format: UdifFormat,
    level: Option<u8>,
    plain: &[u8],
) -> Result<Option<(ChunkType, Vec<u8>)>> {
    #[cfg(not(any(
        feature = "dmg-write-zlib",
        feature = "dmg-write-bzip2",
        feature = "dmg-write-lzma"
    )))]
    let _ = level;
    // Deterministic panic injection for the worker-failure test.
    #[cfg(test)]
    if plain.starts_with(b"fstool-worker-panic") {
        panic!("injected compression worker panic");
    }
    Ok(match format {
        UdifFormat::Udro | UdifFormat::Ufbi => None,
        UdifFormat::Udco => Some((ChunkType::Adc, super::codec::encode_adc(plain))),
        #[cfg(feature = "dmg-write-zlib")]
        UdifFormat::Udzo => {
            #[cfg(feature = "dmg-write-zlib-sirocco")]
            let encoded = sirocco::compress(
                sirocco::Format::Zlib,
                sirocco::deflate::Level::new(level.unwrap_or(6).min(9)),
                plain,
            );
            #[cfg(not(feature = "dmg-write-zlib-sirocco"))]
            let encoded = {
                let mut cfg = compcol::zlib::EncoderConfig::default();
                if let Some(l) = level {
                    cfg.level = l;
                }
                cc_encode::<compcol::zlib::Zlib>(plain, cfg)?
            };
            Some((ChunkType::Zlib, encoded))
        }
        #[cfg(feature = "dmg-write-bzip2")]
        UdifFormat::Udbz => {
            let mut cfg = compcol::bzip2::EncoderConfig::default();
            if let Some(l) = level {
                cfg.level = l;
            }
            Some((
                ChunkType::Bz2,
                cc_encode::<compcol::bzip2::Bzip2>(plain, cfg)?,
            ))
        }
        #[cfg(feature = "dmg-write-lzma")]
        UdifFormat::Ulmo => {
            let mut cfg = compcol::xz::EncoderConfig::default();
            if let Some(l) = level {
                cfg.level = l;
            }
            Some((ChunkType::Lzma, cc_encode::<compcol::xz::Xz>(plain, cfg)?))
        }
        #[cfg(feature = "dmg-write-lzfse")]
        UdifFormat::Ulfo => Some((
            ChunkType::Lzfse,
            cc_encode::<compcol::lzfse::Lzfse>(plain, ())?,
        )),
        // Formats whose codec is compiled out were refused by `validate`;
        // UDRW never reaches the chunker.
        #[allow(unreachable_patterns)]
        other => {
            other.check_writable()?;
            unreachable!("writable format without an encoder arm")
        }
    })
}

#[cfg(any(
    feature = "dmg-write-zlib",
    feature = "dmg-write-bzip2",
    feature = "dmg-write-lzma",
    feature = "dmg-write-lzfse"
))]
#[cfg(any(
    feature = "dmg-write-bzip2",
    feature = "dmg-write-lzma",
    feature = "dmg-write-lzfse",
    all(feature = "dmg-write-zlib", not(feature = "dmg-write-zlib-sirocco"))
))]
fn cc_encode<A: compcol::Algorithm>(plain: &[u8], cfg: A::EncoderConfig) -> Result<Vec<u8>> {
    compcol::vec::compress_to_vec_with::<A>(plain, cfg).map_err(|e| {
        crate::Error::Io(std::io::Error::other(format!(
            "dmg: {} chunk encode failed: {e}",
            A::NAME
        )))
    })
}

/// Escape the five XML-significant characters for a `<string>` body.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// A `<data>` body the way Apple's serialiser lays it out: base64 in
/// 44-column lines indented four tabs, closing tag on its own line.
fn push_data(out: &mut String, bytes: &[u8]) {
    let b64 = crate::base64::encode(bytes);
    out.push_str("\t\t\t\t<data>\n");
    for line in b64.as_bytes().chunks(44) {
        out.push_str("\t\t\t\t");
        // base64 output is ASCII.
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("\t\t\t\t</data>\n");
}

/// The constant `plst` resource `hdiutil` writes.
pub(crate) fn plst_resource() -> super::UdifResource {
    let mut plst = vec![0u8; PLST_LEN];
    plst[PLST_ONES_AT..PLST_ONES_AT + 4].copy_from_slice(&[0, 1, 0, 1]);
    let mut r = super::UdifResource::new("plst", 0, plst);
    r.attributes = 0x0050;
    r
}

/// The plist with caller resources beside `blkx`, through the generic
/// serialiser.
fn build_plist_with(blkx: &[Blkx], extra: &super::UdifResources) -> String {
    let mut res = super::UdifResources::new();
    for b in blkx {
        let mut r = super::UdifResource::new(super::BLKX_RESOURCE, b.id, b.mish.clone());
        r.name = b.name.clone();
        r.cf_name = Some(b.name.clone());
        r.attributes = 0x0050;
        res.entries.push(r);
    }
    if extra.of_kind("plst").next().is_none() {
        res.entries.push(plst_resource());
    }
    res.entries.extend(extra.entries.iter().cloned());
    super::pvalue::write_document(&super::pvalue::Value::Dict(vec![(
        "resource-fork".into(),
        res.to_value(),
    )]))
}

/// The resource-fork plist, in the shape `hdiutil` writes: the `blkx`
/// array, then the constant `plst` resource.
fn build_plist(blkx: &[Blkx]) -> String {
    let mut s = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>resource-fork</key>\n\
         \t<dict>\n\
         \t\t<key>blkx</key>\n\
         \t\t<array>\n",
    );
    for b in blkx {
        let name = xml_escape(&b.name);
        s.push_str(
            "\t\t\t<dict>\n\t\t\t\t<key>Attributes</key>\n\t\t\t\t<string>0x0050</string>\n",
        );
        s.push_str(&format!(
            "\t\t\t\t<key>CFName</key>\n\t\t\t\t<string>{name}</string>\n"
        ));
        s.push_str("\t\t\t\t<key>Data</key>\n");
        push_data(&mut s, &b.mish);
        s.push_str(&format!(
            "\t\t\t\t<key>ID</key>\n\t\t\t\t<string>{}</string>\n\
             \t\t\t\t<key>Name</key>\n\t\t\t\t<string>{name}</string>\n\t\t\t</dict>\n",
            b.id
        ));
    }
    s.push_str(
        "\t\t</array>\n\t\t<key>plst</key>\n\t\t<array>\n\t\t\t<dict>\n\
         \t\t\t\t<key>Attributes</key>\n\t\t\t\t<string>0x0050</string>\n\
         \t\t\t\t<key>Data</key>\n",
    );
    let mut plst = [0u8; PLST_LEN];
    plst[PLST_ONES_AT..PLST_ONES_AT + 4].copy_from_slice(&[0, 1, 0, 1]);
    push_data(&mut s, &plst);
    s.push_str(
        "\t\t\t\t<key>ID</key>\n\t\t\t\t<string>0</string>\n\
         \t\t\t\t<key>Name</key>\n\t\t\t\t<string></string>\n\
         \t\t\t</dict>\n\t\t</array>\n\t</dict>\n</dict>\n</plist>\n",
    );
    s
}

/// Encode every sector of `src` into a UDIF image written to `out`.
///
/// `src.total_size()` must be a non-zero multiple of 512. With
/// [`UdifLayout::Auto`] the source's partition table (if any) picks the
/// layout. The device is read in chunk-sized pieces, so memory stays
/// bounded by [`UdifWriteOptions::chunk_sectors`]. Returns the sink
/// (positioned after the trailer) and a summary; see
/// [`UdifWriter::finish`].
pub fn write_udif<W: Write + Seek>(
    src: &mut dyn BlockDevice,
    out: W,
    opts: &UdifWriteOptions,
) -> Result<(W, UdifSummary)> {
    let total = src.total_size();
    check_length(total)?;
    let resolved;
    let opts = if opts.layout == UdifLayout::Auto && opts.format != UdifFormat::Udrw {
        // Validate first so a bad option is reported before probing.
        opts.validate()?;
        let mut o = opts.clone();
        o.layout = match udif_partition_map(src)? {
            Some(map) => UdifLayout::Map(map),
            None => UdifLayout::WholeDevice,
        };
        resolved = o;
        &resolved
    } else {
        opts
    };
    if let UdifLayout::Map(map) = &opts.layout
        && opts.format != UdifFormat::Udrw
    {
        let end = check_map(map)?;
        if end != total / SECTOR as u64 {
            return Err(crate::Error::InvalidArgument(format!(
                "dmg: the layout map covers {end} sectors but the source has {}",
                total / SECTOR as u64
            )));
        }
    }
    let mut w = UdifWriter::new(out, opts)?;
    let stats = w.stats_handle();
    let mut buf = vec![0u8; (opts.chunk_sectors as usize * SECTOR).max(READ_AHEAD)];
    let mut off = 0u64;
    while off < total {
        let n = buf.len().min((total - off) as usize);
        let t = std::time::Instant::now();
        src.read_at(off, &mut buf[..n])?;
        stats.read_wait(t.elapsed());
        w.write_sectors(&buf[..n])?;
        off += n as u64;
    }
    w.finish()
}

/// Encode exactly `len` bytes read from `src` into a UDIF image written
/// to `out`. `len` must be a non-zero multiple of 512; a source that
/// ends early is an error (`UnexpectedEof`), and nothing past `len` is
/// read. [`UdifLayout::Auto`] is refused (a reader can't be probed).
pub fn write_udif_from_reader<R: Read, W: Write + Seek>(
    mut src: R,
    len: u64,
    out: W,
    opts: &UdifWriteOptions,
) -> Result<(W, UdifSummary)> {
    check_length(len)?;
    let mut w = UdifWriter::new(out, opts)?;
    let stats = w.stats_handle();
    let mut buf = vec![0u8; (opts.chunk_sectors as usize * SECTOR).max(READ_AHEAD)];
    let mut off = 0u64;
    while off < len {
        let n = buf.len().min((len - off) as usize);
        let t = std::time::Instant::now();
        src.read_exact(&mut buf[..n])?;
        stats.read_wait(t.elapsed());
        w.write_sectors(&buf[..n])?;
        off += n as u64;
    }
    w.finish()
}

fn check_length(len: u64) -> Result<()> {
    if len == 0 || !len.is_multiple_of(SECTOR as u64) {
        return Err(crate::Error::InvalidArgument(format!(
            "dmg: source length {len} is not a non-zero multiple of 512 bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::DmgBackend;
    use std::io::Cursor;

    /// A small disk with every kind of region: leading zeros, text,
    /// noise, a long zero gap, a data run longer than one chunk, and a
    /// trailing lone data sector.
    fn sample_disk() -> Vec<u8> {
        let mut d = vec![0u8; 3 * SECTOR];
        let mut text = Vec::new();
        for i in 0..1500 {
            text.extend_from_slice(format!("line {i} of a compressible text\n").as_bytes());
        }
        d.extend_from_slice(&text);
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..40_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            d.push(x as u8);
        }
        d.resize(d.len().next_multiple_of(SECTOR), 0x5A);
        d.extend_from_slice(&vec![0u8; 300 * SECTOR]);
        for i in 0..(70 * SECTOR) {
            d.push((i / 700) as u8 | 1);
        }
        d.extend_from_slice(&vec![0u8; 2 * SECTOR]);
        d.extend_from_slice(&[0xEE; SECTOR]);
        d
    }

    fn opts(format: UdifFormat) -> UdifWriteOptions {
        UdifWriteOptions {
            format,
            chunk_sectors: 32,
            segment_id: Some([7; 16]),
            ..Default::default()
        }
    }

    fn roundtrip(o: &UdifWriteOptions, disk: &[u8]) -> (Vec<u8>, UdifSummary) {
        let (cur, summary) = write_udif_from_reader(
            Cursor::new(disk),
            disk.len() as u64,
            Cursor::new(Vec::new()),
            o,
        )
        .unwrap();
        let img = cur.into_inner();
        assert_eq!(img.len() as u64, summary.bytes_written);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rt.dmg");
        std::fs::write(&path, &img).unwrap();
        let mut dmg = DmgBackend::open(&path).unwrap();
        assert_eq!(dmg.total_size(), disk.len() as u64);
        let mut back = vec![0u8; disk.len()];
        dmg.read_at(0, &mut back).unwrap();
        assert!(back == disk, "{} round trip differs", o.format.name());
        let t = dmg.trailer();
        assert_eq!(t.sector_count, summary.sector_count);
        assert_eq!(t.segment_id, [7; 16]);
        (img, summary)
    }

    fn all_writable() -> Vec<UdifFormat> {
        [
            UdifFormat::Udro,
            UdifFormat::Udco,
            UdifFormat::Udzo,
            UdifFormat::Udbz,
            UdifFormat::Ulmo,
            UdifFormat::Ulfo,
            UdifFormat::Ufbi,
        ]
        .into_iter()
        .filter(|f| f.writable())
        .collect()
    }

    #[test]
    fn every_writable_format_roundtrips() {
        let disk = sample_disk();
        for f in all_writable() {
            // Reading back needs the matching decoder; each write feature
            // implies it.
            let (_, s) = roundtrip(&opts(f), &disk);
            assert!(s.chunk_count > 4, "{}: expected several chunks", f.name());
            if !matches!(f, UdifFormat::Udro | UdifFormat::Ufbi) {
                assert!(s.data_fork_length < disk.len() as u64 / 2, "{}", f.name());
            }
        }
    }

    #[test]
    fn checksums_match_hdiutil_definitions() {
        let disk = sample_disk();
        for zero_runs in [ZeroRunEncoding::ZeroFill, ZeroRunEncoding::Ignore] {
            let mut o = opts(UdifFormat::Udro);
            o.zero_runs = zero_runs;
            let (img, s) = roundtrip(&o, &disk);
            let t = KolyTrailer::decode(&img[img.len() - 512..]).unwrap();
            // Data fork CRC over the stored bytes.
            let fork = &img[..t.data_fork_length as usize];
            assert_eq!(s.data_fork_crc32, Some(crate::crc::crc32(fork)));
            assert_eq!(t.data_checksum_type, 2);
            assert_eq!(t.data_checksum[..4], crate::crc::crc32(fork).to_be_bytes());
            // Partition CRC: plaintext, minus "ignore" sectors.
            let expect = match zero_runs {
                ZeroRunEncoding::ZeroFill => crate::crc::crc32(&disk),
                ZeroRunEncoding::Ignore => {
                    let nz: Vec<u8> = disk
                        .chunks(SECTOR)
                        .filter(|s| !is_zero(s))
                        .flatten()
                        .copied()
                        .collect();
                    crate::crc::crc32(&nz)
                }
            };
            assert_eq!(s.partition_crc32, Some(expect));
            // Master CRC over the big-endian partition checksums.
            assert_eq!(
                t.master_checksum[..4],
                crate::crc::crc32(&expect.to_be_bytes()).to_be_bytes()
            );
        }
    }

    #[test]
    fn zero_sectors_are_never_compressed() {
        let mut disk = vec![0u8; 100 * SECTOR];
        disk[50 * SECTOR] = 1;
        let mut o = opts(UdifFormat::Udco);
        o.zero_runs = ZeroRunEncoding::Ignore;
        let (img, s) = roundtrip(&o, &disk);
        // zero(50) + data(1) + zero(49)
        assert_eq!(s.chunk_count, 3);
        // One stored sector of ADC payload at most.
        assert!(s.data_fork_length < 64, "{}", s.data_fork_length);
        let t = KolyTrailer::decode(&img[img.len() - 512..]).unwrap();
        let plist = std::str::from_utf8(
            &img[t.xml_offset as usize..(t.xml_offset + t.xml_length) as usize],
        )
        .unwrap();
        let raw = crate::base64::decode(
            &super::super::plist::extract_blkx_data_entries(plist).unwrap()[0],
        )
        .unwrap();
        let m = super::super::mish::decode_mish(&raw).unwrap();
        let kinds: Vec<ChunkType> = m.chunks.iter().map(|c| c.kind).collect();
        assert_eq!(
            kinds,
            [ChunkType::Ignored, ChunkType::Adc, ChunkType::Ignored]
        );
    }

    #[test]
    fn incompressible_chunks_are_stored_raw() {
        let mut x: u64 = 1;
        let disk: Vec<u8> = (0..16 * SECTOR)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        for f in all_writable() {
            let (_, s) = roundtrip(&opts(f), &disk);
            assert_eq!(s.data_fork_length, disk.len() as u64, "{}", f.name());
        }
    }

    #[test]
    fn checksum_none_writes_type_zero() {
        let disk = sample_disk();
        let mut o = opts(UdifFormat::Udro);
        o.checksum = UdifChecksum::None;
        let (img, s) = roundtrip(&o, &disk);
        let t = KolyTrailer::decode(&img[img.len() - 512..]).unwrap();
        assert_eq!((t.data_checksum_type, t.master_checksum_type), (0, 0));
        assert_eq!(s.master_crc32, None);
    }

    #[test]
    fn nonzero_start_offset_is_recorded() {
        let disk = sample_disk();
        let mut cur = Cursor::new(vec![0xCCu8; 1000]);
        cur.seek(std::io::SeekFrom::End(0)).unwrap();
        let (cur, _) =
            write_udif_from_reader(&disk[..], disk.len() as u64, cur, &opts(UdifFormat::Udco))
                .unwrap();
        let img = cur.into_inner();
        let t = KolyTrailer::decode(&img[img.len() - 512..]).unwrap();
        assert_eq!(t.data_fork_offset, 1000);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("off.dmg");
        std::fs::write(&path, &img).unwrap();
        let mut dmg = DmgBackend::open(&path).unwrap();
        let mut back = vec![0u8; disk.len()];
        dmg.read_at(0, &mut back).unwrap();
        assert!(back == disk);
    }

    #[test]
    fn block_device_source() {
        let disk = sample_disk();
        let mut dev = crate::block::MemoryBackend::new(disk.len() as u64);
        dev.write_at(0, &disk).unwrap();
        let (cur, s) =
            write_udif(&mut dev, Cursor::new(Vec::new()), &opts(UdifFormat::Udco)).unwrap();
        assert_eq!(s.sector_count, (disk.len() / SECTOR) as u64);
        assert!(!cur.into_inner().is_empty());
    }

    #[test]
    fn options_are_checked() {
        let bad = |f: &dyn Fn(&mut UdifWriteOptions)| {
            let mut o = UdifWriteOptions {
                format: UdifFormat::Udco,
                ..Default::default()
            };
            f(&mut o);
            o.validate().unwrap_err()
        };
        assert!(matches!(
            bad(&|o| o.chunk_sectors = 0),
            crate::Error::InvalidArgument(_)
        ));
        assert!(matches!(
            bad(&|o| o.chunk_sectors = MAX_WRITE_CHUNK_SECTORS + 1),
            crate::Error::InvalidArgument(_)
        ));
        assert!(matches!(
            bad(&|o| o.level = Some(3)),
            crate::Error::InvalidArgument(_)
        ));
        assert!(matches!(
            bad(&|o| o.partition_name = String::new()),
            crate::Error::InvalidArgument(_)
        ));
        #[cfg(not(feature = "dmg-write-lzfse"))]
        assert!(matches!(
            bad(&|o| o.format = UdifFormat::Ulfo),
            crate::Error::Unsupported(_)
        ));
        if UdifFormat::Udzo.writable() {
            let mut o = UdifWriteOptions {
                level: Some(10),
                ..Default::default()
            };
            assert!(o.validate().is_err());
            o.level = Some(9);
            o.validate().unwrap();
        } else {
            assert!(matches!(
                UdifWriteOptions::default().validate(),
                Err(crate::Error::Unsupported(_))
            ));
        }
        // Geometry of the source.
        let e = write_udif_from_reader(
            &[0u8; 100][..],
            100,
            Cursor::new(Vec::new()),
            &opts(UdifFormat::Udro),
        );
        assert!(matches!(e, Err(crate::Error::InvalidArgument(_))));
        let e =
            write_udif_from_reader(&[][..], 0, Cursor::new(Vec::new()), &opts(UdifFormat::Udro));
        assert!(matches!(e, Err(crate::Error::InvalidArgument(_))));
        let mut w = UdifWriter::new(Cursor::new(Vec::new()), &opts(UdifFormat::Udro)).unwrap();
        assert!(w.write_sectors(&[1u8; 513]).is_err());
        // A rejected argument writes nothing, so the writer stays usable.
        w.write_sectors(&[1u8; 512]).unwrap();
        w.finish().unwrap();
        // A sink failure, by contrast, poisons it.
        let sink = FailingSink {
            inner: Cursor::new(Vec::new()),
            budget: 0,
        };
        let mut o = opts(UdifFormat::Udro);
        o.chunk_sectors = 1;
        let mut w = UdifWriter::new(sink, &o).unwrap();
        assert!(matches!(
            w.write_sectors(&[1u8; 512]),
            Err(crate::Error::Io(_))
        ));
        assert!(w.write_sectors(&[1u8; 512]).is_err());
        assert!(w.finish().is_err());
    }

    #[test]
    fn short_source_is_an_error() {
        let e = write_udif_from_reader(
            &[1u8; 1024][..],
            4096,
            Cursor::new(Vec::new()),
            &opts(UdifFormat::Udro),
        );
        assert!(
            matches!(e, Err(crate::Error::Io(ref io)) if io.kind() == std::io::ErrorKind::UnexpectedEof)
        );
    }

    /// A sink that fails once `budget` bytes have been accepted.
    #[derive(Debug)]
    struct FailingSink {
        inner: Cursor<Vec<u8>>,
        budget: usize,
    }
    impl Write for FailingSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.inner.get_ref().len() + buf.len() > self.budget {
                return Err(std::io::Error::other("disk full"));
            }
            self.inner.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Seek for FailingSink {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    #[test]
    fn sink_errors_propagate_at_every_stage() {
        let disk = sample_disk();
        // Full size of a successful image, to place failures in the data
        // fork, the plist and the trailer.
        let (cur, s) = write_udif_from_reader(
            &disk[..],
            disk.len() as u64,
            Cursor::new(Vec::new()),
            &opts(UdifFormat::Udro),
        )
        .unwrap();
        let total = cur.into_inner().len();
        for budget in [
            0,
            1000,
            s.data_fork_length as usize + 10,
            total - 100,
            total - 1,
        ] {
            let sink = FailingSink {
                inner: Cursor::new(Vec::new()),
                budget,
            };
            let e =
                write_udif_from_reader(&disk[..], disk.len() as u64, sink, &opts(UdifFormat::Udro))
                    .unwrap_err();
            assert!(matches!(e, crate::Error::Io(_)), "budget {budget}: {e}");
        }
    }

    #[test]
    fn source_errors_propagate() {
        struct FailingRead(usize);
        impl Read for FailingRead {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0 == 0 {
                    return Err(std::io::Error::other("read failed"));
                }
                let n = buf.len().min(self.0);
                buf[..n].fill(0x11);
                self.0 -= n;
                Ok(n)
            }
        }
        let e = write_udif_from_reader(
            FailingRead(64 * SECTOR),
            1024 * SECTOR as u64,
            Cursor::new(Vec::new()),
            &opts(UdifFormat::Udro),
        )
        .unwrap_err();
        assert!(matches!(e, crate::Error::Io(ref io) if io.to_string() == "read failed"));
    }

    #[test]
    fn partition_name_is_escaped() {
        let disk = vec![1u8; 4 * SECTOR];
        let mut o = opts(UdifFormat::Udro);
        o.partition_name = "a <b> & 'c'".into();
        let (img, _) = roundtrip(&o, &disk);
        let s = String::from_utf8_lossy(&img);
        assert!(s.contains("<string>a &lt;b&gt; &amp; &apos;c&apos;</string>"));
    }

    #[test]
    fn format_names_roundtrip() {
        for f in [
            UdifFormat::Udro,
            UdifFormat::Udco,
            UdifFormat::Udzo,
            UdifFormat::Udbz,
            UdifFormat::Ulfo,
            UdifFormat::Ulmo,
            UdifFormat::Ufbi,
            UdifFormat::Udrw,
        ] {
            assert_eq!(UdifFormat::from_name(&f.name().to_lowercase()), Some(f));
        }
        assert_eq!(UdifFormat::from_name("UDTO"), None);
        assert_eq!(
            UdifFormat::Ulfo.writable(),
            cfg!(feature = "dmg-write-lzfse")
        );
    }

    /// Pull every blkx entry's (Name, ID, decoded mish) out of an image.
    fn blkx_entries(img: &[u8]) -> Vec<(String, i32, super::super::mish::Mish, Vec<u8>)> {
        let t = KolyTrailer::decode(&img[img.len() - 512..]).unwrap();
        let plist = std::str::from_utf8(
            &img[t.xml_offset as usize..(t.xml_offset + t.xml_length) as usize],
        )
        .unwrap();
        let datas = super::super::plist::extract_blkx_data_entries(plist).unwrap();
        let blkx = &plist[..plist.find("<key>plst</key>").unwrap()];
        let names: Vec<&str> = blkx
            .split("<key>Name</key>")
            .skip(1)
            .map(|s| {
                let s = &s[s.find("<string>").unwrap() + 8..];
                &s[..s.find("</string>").unwrap()]
            })
            .collect();
        let ids: Vec<i32> = blkx
            .split("<key>ID</key>")
            .skip(1)
            .map(|s| {
                let s = &s[s.find("<string>").unwrap() + 8..];
                s[..s.find("</string>").unwrap()].parse().unwrap()
            })
            .collect();
        assert_eq!(names.len(), datas.len());
        names
            .into_iter()
            .zip(ids)
            .zip(datas)
            .map(|((n, id), d)| {
                let raw = crate::base64::decode(&d).unwrap();
                (
                    n.to_string(),
                    id,
                    super::super::mish::decode_mish(&raw).unwrap(),
                    raw,
                )
            })
            .collect()
    }

    #[test]
    fn plist_carries_hdiutils_plst_resource() {
        let disk = vec![1u8; 4 * SECTOR];
        let (img, _) = roundtrip(&opts(UdifFormat::Udro), &disk);
        let t = KolyTrailer::decode(&img[img.len() - 512..]).unwrap();
        let plist = std::str::from_utf8(
            &img[t.xml_offset as usize..(t.xml_offset + t.xml_length) as usize],
        )
        .unwrap();
        let tail = &plist[plist.find("<key>plst</key>").unwrap()..];
        let body = &tail[tail.find("<data>").unwrap() + 6..tail.find("</data>").unwrap()];
        let plst = crate::base64::decode(body).unwrap();
        assert_eq!(plst.len(), PLST_LEN);
        let ones: Vec<usize> = (0..plst.len()).filter(|&i| plst[i] != 0).collect();
        assert_eq!(ones, [517, 519]);
        // Whole-device images use hdiutil's device variant and descriptor.
        assert_eq!(t.image_variant, KOLY_IMAGE_VARIANT_DEVICE);
        let e = blkx_entries(&img);
        assert_eq!(e.len(), 1);
        assert_eq!((e[0].0.as_str(), e[0].1), ("whole disk (Apple_HFS : 0)", 0));
        assert_eq!(e[0].3[0x24..0x28], (-2i32).to_be_bytes());
    }

    #[test]
    fn md5_checksums_match_hdiutil_definitions() {
        use crate::md5::md5;
        let disk = sample_disk();
        for f in [UdifFormat::Udro, UdifFormat::Udco, UdifFormat::Ufbi] {
            let mut o = opts(f);
            o.checksum = UdifChecksum::Md5;
            o.zero_runs = ZeroRunEncoding::Ignore;
            let (img, s) = roundtrip(&o, &disk);
            let t = KolyTrailer::decode(&img[img.len() - 512..]).unwrap();
            let fork = &img[..t.data_fork_length as usize];
            assert_eq!((t.data_checksum_type, t.data_checksum_size), (4, 128));
            assert_eq!(t.data_checksum[..16], md5(fork));
            assert_eq!(s.data_fork_md5, Some(md5(fork)));
            // Partition MD5 skips ignored sectors (UFBI ignores none).
            let plain: Vec<u8> = if f == UdifFormat::Ufbi {
                disk.clone()
            } else {
                disk.chunks(SECTOR)
                    .filter(|s| !is_zero(s))
                    .flatten()
                    .copied()
                    .collect()
            };
            let e = blkx_entries(&img);
            assert_eq!(e[0].3[0x40..0x48], [0, 0, 0, 4, 0, 0, 0, 128]);
            assert_eq!(e[0].3[0x48..0x58], md5(&plain));
            assert_eq!(t.master_checksum_type, 4);
            assert_eq!(t.master_checksum[..16], md5(&md5(&plain)));
            assert_eq!(s.master_md5, Some(md5(&md5(&plain))));
            assert_eq!(s.checksum, UdifChecksum::Md5);
            assert_eq!(s.master_crc32, None);
        }
    }

    #[test]
    fn ufbi_stores_every_sector_raw_with_md5() {
        let disk = sample_disk();
        // Default checksum (CRC-32) is upgraded to MD5 for UFBI.
        let (img, s) = roundtrip(&opts(UdifFormat::Ufbi), &disk);
        assert_eq!(s.checksum, UdifChecksum::Md5);
        assert_eq!(s.data_fork_length, disk.len() as u64);
        let e = blkx_entries(&img);
        assert!(e[0].2.chunks.iter().all(|c| c.kind == ChunkType::Raw));
        // No compressed chunks: buffers_needed is 0, as hdiutil writes.
        assert_eq!(e[0].3[0x20..0x24], [0; 4]);
        // An explicit None is honoured.
        let mut o = opts(UdifFormat::Ufbi);
        o.checksum = UdifChecksum::None;
        let (img, _) = roundtrip(&o, &disk);
        let t = KolyTrailer::decode(&img[img.len() - 512..]).unwrap();
        assert_eq!(t.master_checksum_type, 0);
    }

    #[test]
    fn udrw_is_the_bare_sectors() {
        let disk = sample_disk();
        let mut o = opts(UdifFormat::Udrw);
        o.layout = UdifLayout::Auto; // does not apply to UDRW
        let (cur, s) =
            write_udif_from_reader(&disk[..], disk.len() as u64, Cursor::new(Vec::new()), &o)
                .unwrap();
        assert!(cur.into_inner() == disk);
        assert_eq!(s.bytes_written, disk.len() as u64);
        assert_eq!((s.blkx_count, s.plist_length), (0, 0));
        let mut o = opts(UdifFormat::Udrw);
        o.level = Some(1);
        assert!(matches!(
            o.validate(),
            Err(crate::Error::InvalidArgument(_))
        ));
    }

    /// A GPT disk: MBR, headers, tables, two partitions with a gap.
    fn gpt_disk() -> crate::block::MemoryBackend {
        use crate::part::{Gpt, Partition, PartitionKind, PartitionTable};
        let mut dev = crate::block::MemoryBackend::new(4096 * SECTOR as u64);
        let hfs = PartitionKind::Gpt(
            uuid::Uuid::parse_str("48465300-0000-11AA-AA11-00306543ECAC").unwrap(),
        );
        let mut a = Partition::new(40, 1000, hfs);
        a.name = Some("disk image".into());
        let b = Partition::new(1100, 2000, PartitionKind::EfiSystem);
        Gpt::build(vec![a, b]).unwrap().write(&mut dev).unwrap();
        let disk = sample_disk();
        // sample_disk is ~549 sectors: fits both partitions.
        dev.write_at(40 * SECTOR as u64, &disk).unwrap();
        dev.write_at(1100 * SECTOR as u64, &disk).unwrap();
        // Stale bytes in the free gap must survive too.
        dev.write_at(1050 * SECTOR as u64, b"stale").unwrap();
        dev
    }

    #[test]
    fn auto_layout_writes_one_blkx_per_region() {
        let mut dev = gpt_disk();
        let mut whole = vec![0u8; dev.total_size() as usize];
        dev.read_at(0, &mut whole).unwrap();
        for f in all_writable() {
            let mut o = opts(f);
            o.layout = UdifLayout::Auto;
            let (cur, s) = write_udif(&mut dev, Cursor::new(Vec::new()), &o).unwrap();
            let img = cur.into_inner();
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("p.dmg");
            std::fs::write(&path, &img).unwrap();
            let mut dmg = DmgBackend::open(&path).unwrap();
            let mut back = vec![0u8; whole.len()];
            dmg.read_at(0, &mut back).unwrap();
            assert!(back == whole, "{} partitioned round trip differs", f.name());
            assert_eq!(dmg.trailer().image_variant, KOLY_IMAGE_VARIANT_PARTITIONED);

            let e = blkx_entries(&img);
            assert_eq!(s.blkx_count, e.len());
            let names: Vec<&str> = e.iter().map(|x| x.0.as_str()).collect();
            assert_eq!(
                names,
                [
                    "Protective Master Boot Record (MBR : 0)",
                    "GPT Header (Primary GPT Header : 1)",
                    "GPT Partition Data (Primary GPT Table : 2)",
                    " (Apple_Free : 3)",
                    "disk image (Apple_HFS : 4)",
                    " (Apple_Free : 5)",
                    " (EFI : 6)",
                    " (Apple_Free : 7)",
                    "GPT Partition Data (Backup GPT Table : 8)",
                    "GPT Header (Backup GPT Header : 9)",
                ]
            );
            let ids: Vec<i32> = e.iter().map(|x| x.1).collect();
            assert_eq!(ids, (-1..9).collect::<Vec<_>>());
            let mut master = Digest::new(s.checksum);
            for (i, (_, _, m, raw)) in e.iter().enumerate() {
                assert_eq!(raw[0x24..0x28], (i as i32).to_be_bytes());
                // Chunks never cross the region and cover it exactly.
                let covered: u64 = m.chunks.iter().map(|c| c.sector_count).sum();
                assert_eq!(covered, m.sector_count);
                assert!(m.chunks.iter().all(|c| {
                    c.virtual_sector_start >= m.first_sector
                        && c.virtual_sector_start + c.sector_count
                            <= m.first_sector + m.sector_count
                }));
                master.update(&raw[0x48..0x48 + raw[0x47] as usize / 8]);
            }
            // The all-zero free gap before partition 1 is ignored, not
            // stored, whatever zero_runs says (except UFBI, which keeps
            // every sector).
            if f != UdifFormat::Ufbi {
                assert!(e[3].2.chunks.iter().all(|c| c.kind == ChunkType::Ignored));
                assert_eq!(e[3].3[0x48..0x4C], [0; 4]);
            }
            let t = dmg.trailer();
            let m = master.finish();
            assert_eq!(t.master_checksum, m.bytes());
        }
    }

    #[test]
    fn explicit_maps_are_checked() {
        let map = |spans: &[(u64, u64)]| {
            UdifLayout::Map(
                spans
                    .iter()
                    .map(|&(s, n)| UdifMapEntry::new("x", s, n))
                    .collect(),
            )
        };
        let check = |layout: UdifLayout| {
            let mut o = opts(UdifFormat::Udro);
            o.layout = layout;
            o.validate()
        };
        check(map(&[(0, 4), (4, 4)])).unwrap();
        for bad in [
            map(&[]),
            map(&[(1, 4)]),
            map(&[(0, 4), (5, 4)]),
            map(&[(0, 4), (2, 4)]),
            map(&[(0, 0)]),
            map(&[(0, u64::MAX), (u64::MAX, 1)]),
        ] {
            assert!(
                matches!(check(bad.clone()), Err(crate::Error::InvalidArgument(_))),
                "{bad:?}"
            );
        }
        let mut o = opts(UdifFormat::Udro);
        o.layout = map(&[(0, 4), (4, 4)]);
        // Too many sectors: refused up front, without poisoning.
        let mut w = UdifWriter::new(Cursor::new(Vec::new()), &o).unwrap();
        assert!(matches!(
            w.write_sectors(&[1u8; 9 * SECTOR]),
            Err(crate::Error::InvalidArgument(_))
        ));
        w.write_sectors(&[1u8; 6 * SECTOR]).unwrap();
        // Too few at finish.
        assert!(matches!(w.finish(), Err(crate::Error::InvalidArgument(_))));
        // A source whose size doesn't match the map is refused before
        // anything is written.
        let mut dev = crate::block::MemoryBackend::new(16 * SECTOR as u64);
        let e = write_udif(&mut dev, Cursor::new(Vec::new()), &o).unwrap_err();
        assert!(matches!(e, crate::Error::InvalidArgument(_)));
        // Auto can't be resolved without a device.
        o.layout = UdifLayout::Auto;
        assert!(UdifWriter::new(Cursor::new(Vec::new()), &o).is_err());
        // Exactly the map: fine, with each entry's ID / descriptor.
        let mut m = vec![UdifMapEntry::new("a", 0, 4), UdifMapEntry::new("b", 4, 4)];
        m[1].id = 7;
        m[1].descriptor = 9;
        o.layout = UdifLayout::Map(m);
        let mut w = UdifWriter::new(Cursor::new(Vec::new()), &o).unwrap();
        w.write_sectors(&[1u8; 8 * SECTOR]).unwrap();
        let (cur, s) = w.finish().unwrap();
        assert_eq!(s.blkx_count, 2);
        let img = cur.into_inner();
        let e = blkx_entries(&img);
        assert_eq!((e[1].0.as_str(), e[1].1), ("b", 7));
        assert_eq!(e[1].3[0x24..0x28], 9i32.to_be_bytes());
        assert_eq!(e[1].2.first_sector, 4);
    }

    #[test]
    fn auto_layout_on_a_bare_volume_is_whole_device() {
        let mut dev = crate::block::MemoryBackend::new(64 * SECTOR as u64);
        dev.write_at(0, &[0xAB; 64 * SECTOR]).unwrap();
        let mut o = opts(UdifFormat::Udco);
        o.layout = UdifLayout::Auto;
        let (cur, s) = write_udif(&mut dev, Cursor::new(Vec::new()), &o).unwrap();
        assert_eq!(s.blkx_count, 1);
        assert!(s.partition_crc32.is_some());
        let img = cur.into_inner();
        assert_eq!(blkx_entries(&img)[0].0, "whole disk (Apple_HFS : 0)");
    }

    #[test]
    fn parallel_udzo_matches_sequential() {
        let disk = sample_disk();
        let mut one = opts(UdifFormat::Udzo);
        one.threads = 1;
        let mut many = one.clone();
        many.threads = 4;
        let (a, sa) = roundtrip(&one, &disk);
        let (b, sb) = roundtrip(&many, &disk);
        assert!(a == b, "parallel UDZO output differs from sequential");
        assert_eq!(sa.chunk_count, sb.chunk_count);
        assert_eq!(sa.data_fork_crc32, sb.data_fork_crc32);
        assert_eq!(sa.master_crc32, sb.master_crc32);
    }

    #[cfg(feature = "udif-stats")]
    #[test]
    fn stats_reporter_stops_when_the_last_handle_drops() {
        let (stats, alive) = super::udif_stats::Stats::for_test();
        let clone = clone_stats(&stats);
        assert!(alive.load(std::sync::atomic::Ordering::Relaxed));
        drop(stats);
        assert!(
            alive.load(std::sync::atomic::Ordering::Relaxed),
            "a live clone must keep the reporter running"
        );
        drop(clone);
        for _ in 0..100 {
            if !alive.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("stats reporter did not stop after the last handle dropped");
    }

    #[test]
    fn worker_panic_returns_error_instead_of_hanging() {
        let mut disk = vec![0x5Au8; 2 * SECTOR];
        let marker = b"fstool-worker-panic";
        disk[..marker.len()].copy_from_slice(marker);
        let mut o = opts(UdifFormat::Udzo);
        o.threads = 3;
        let (tx, rx) = std::sync::mpsc::channel();
        let h = std::thread::spawn(move || {
            let mut dev = crate::block::MemoryBackend::new(disk.len() as u64);
            dev.write_at(0, &disk).unwrap();
            let r = write_udif(&mut dev, Cursor::new(Vec::new()), &o);
            tx.send(r.is_err()).unwrap();
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(10))
                .expect("worker panic left the writer blocked"),
            "worker panic should surface as an error"
        );
        h.join().unwrap();
    }

    #[test]
    fn parallel_udzo_matches_sequential_across_regions() {
        // `Gpt::build` generates fresh GUIDs, so build the source once and
        // feed both writers identical bytes.
        let mut src = gpt_disk();
        let mut bytes = vec![0u8; src.total_size() as usize];
        src.read_at(0, &mut bytes).unwrap();
        let mut d1 = crate::block::MemoryBackend::new(bytes.len() as u64);
        d1.write_at(0, &bytes).unwrap();
        let mut d2 = crate::block::MemoryBackend::new(bytes.len() as u64);
        d2.write_at(0, &bytes).unwrap();

        let mut one = opts(UdifFormat::Udzo);
        one.layout = UdifLayout::Auto;
        one.threads = 1;
        let mut many = one.clone();
        many.threads = 4;
        let (c1, _) = write_udif(&mut d1, Cursor::new(Vec::new()), &one).unwrap();
        let (c2, _) = write_udif(&mut d2, Cursor::new(Vec::new()), &many).unwrap();
        assert!(
            c1.into_inner() == c2.into_inner(),
            "parallel region output differs"
        );
    }

    #[test]
    fn threads_option_is_checked() {
        let mut o = opts(UdifFormat::Udzo);
        o.threads = MAX_WRITE_THREADS + 1;
        assert!(matches!(
            o.validate(),
            Err(crate::Error::InvalidArgument(_))
        ));
        o.threads = MAX_WRITE_THREADS;
        o.validate().unwrap();
        o.threads = 0;
        o.validate().unwrap();
    }

    #[test]
    fn parallel_udzo_matches_sequential_alternating_zero_runs() {
        // Many zero-run boundaries: 1 MiB data / 3 MiB zeros, repeated.
        let mut disk = Vec::new();
        for _ in 0..16 {
            let mut data = vec![0x5Au8; 1024 * 1024];
            for (i, b) in data.iter_mut().enumerate() {
                *b = b.wrapping_add((i % 251) as u8);
            }
            disk.extend_from_slice(&data);
            disk.extend_from_slice(&vec![0u8; 3 * 1024 * 1024]);
        }
        let mut one = opts(UdifFormat::Udzo);
        one.chunk_sectors = 2048;
        one.threads = 1;
        let mut many = one.clone();
        many.threads = 3;
        let (a, sa) = roundtrip(&one, &disk);
        let (b, sb) = roundtrip(&many, &disk);
        assert!(a == b, "parallel alternating-zero output differs");
        assert_eq!(sa.chunk_count, sb.chunk_count);
        assert_eq!(sa.data_fork_crc32, sb.data_fork_crc32);
        assert_eq!(sa.master_crc32, sb.master_crc32);
    }

    #[test]
    fn short_zero_runs_are_folded_into_data_chunks() {
        // 8 × (16 KiB data + 8 KiB zeros) + one data sector. Each hole is
        // far below the coalescing threshold, so the whole image is one
        // chunk instead of 17 tiny data/zero entries.
        let mut disk = Vec::new();
        for round in 0..8u8 {
            for i in 0..32 * SECTOR {
                disk.push(round.wrapping_mul(17).wrapping_add(i as u8) | 1);
            }
            disk.extend(std::iter::repeat_n(0u8, 8 * SECTOR));
        }
        disk.extend(std::iter::repeat_n(0x5Au8, SECTOR));
        let mut o = opts(UdifFormat::Udzo);
        o.chunk_sectors = 2048;
        let (_, s) = roundtrip(&o, &disk);
        assert_eq!(s.chunk_count, 1);
        assert_eq!(s.partition_crc32, Some(crate::crc::crc32(&disk)));
    }

    #[test]
    fn long_zero_runs_are_still_elided() {
        // A run over the coalescing threshold keeps its compact `Zero`
        // entry rather than becoming (compressible) data.
        let mut disk = vec![0x7Fu8; 4 * SECTOR];
        disk.extend(std::iter::repeat_n(0u8, 2048 * SECTOR));
        disk.extend(std::iter::repeat_n(0x11u8, 4 * SECTOR));
        let mut o = opts(UdifFormat::Udzo);
        o.chunk_sectors = 2048;
        let (_, s) = roundtrip(&o, &disk);
        assert_eq!(s.chunk_count, 3);
        assert_eq!(s.partition_crc32, Some(crate::crc::crc32(&disk)));
    }

    #[test]
    fn parallel_udzo_matches_sequential_short_zero_runs() {
        // Alternate small data and zero runs so coalescing, chunk
        // boundaries, zero entries and the parallel window interact.
        let mut disk = Vec::new();
        for i in 0..64u32 {
            for j in 0..4 * SECTOR {
                disk.push((i as u8).wrapping_mul(31).wrapping_add(j as u8) | 1);
            }
            disk.extend(std::iter::repeat_n(0u8, 2 * SECTOR));
        }
        let mut one = opts(UdifFormat::Udzo);
        one.chunk_sectors = 32;
        one.threads = 1;
        let mut many = one.clone();
        many.threads = 3;
        let (a, sa) = roundtrip(&one, &disk);
        let (b, sb) = roundtrip(&many, &disk);
        assert!(a == b, "parallel short-zero output differs");
        assert_eq!(sa.chunk_count, sb.chunk_count);
        assert_eq!(sa.data_fork_crc32, sb.data_fork_crc32);
        assert_eq!(sa.partition_crc32, sb.partition_crc32);
        assert_eq!(sa.master_crc32, sb.master_crc32);
    }
}
