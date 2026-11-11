//! Streaming container conversion.

use std::path::Path;

#[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
use std::io::Write as _;

use super::{COPY_CHUNK, open_source, same_file, write_beside};
use crate::Result;
use crate::block::BlockDevice;

/// A container kind, for a conversion target (and as reported for a
/// source).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ImageKind {
    /// Bare sectors in a file.
    Raw,
    /// Apple UDIF (`.dmg`); the format is [`ConvertOptions::udif`]'s.
    Udif,
    /// Apple `.sparseimage`.
    SparseImage,
    /// Apple `.sparsebundle` (a directory).
    SparseBundle,
    /// qcow2.
    Qcow2,
    /// Any other source container fstool reads (LUKS, DiskCopy, split
    /// archives, …). Not a valid target.
    Other,
}

impl ImageKind {
    /// The target kind a destination's extension names: `.dmg` → UDIF,
    /// `.sparseimage`, `.sparsebundle`, `.qcow2` / `.qcow` / `.q2`, and
    /// anything else raw.
    pub fn from_extension(path: &Path) -> Self {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase);
        match ext.as_deref() {
            Some("dmg") => Self::Udif,
            Some("sparseimage") => Self::SparseImage,
            Some("sparsebundle") => Self::SparseBundle,
            Some("qcow2" | "qcow" | "q2") => Self::Qcow2,
            _ => Self::Raw,
        }
    }

    /// The kind of an existing image, by content.
    pub fn detect(path: &Path) -> Result<Self> {
        #[cfg(feature = "sparse-image")]
        {
            if crate::block::SparseBundleBackend::probe(path)? {
                return Ok(Self::SparseBundle);
            }
            if crate::block::SparseImageBackend::probe(path)? {
                return Ok(Self::SparseImage);
            }
        }
        if super::is_udif(path)? {
            return Ok(Self::Udif);
        }
        #[cfg(feature = "dmg")]
        if crate::block::dmg::probe_encrypted(path)? {
            return Ok(Self::Other);
        }
        #[cfg(feature = "qcow2")]
        if crate::block::Qcow2Backend::probe(path)? {
            return Ok(Self::Qcow2);
        }
        Ok(if path.is_file() {
            // Raw, or a container fstool unwraps (LUKS, DiskCopy, …).
            let mut dev = crate::block::FileBackend::open_read_only(path)?;
            let mut head = [0u8; 6];
            let n = dev.total_size().min(6) as usize;
            dev.read_at(0, &mut head[..n])?;
            if &head == b"LUKS\xba\xbe" {
                Self::Other
            } else {
                Self::Raw
            }
        } else {
            Self::Other
        })
    }

    /// A short name (`"raw"`, `"udif"`, …).
    pub fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Udif => "udif",
            Self::SparseImage => "sparseimage",
            Self::SparseBundle => "sparsebundle",
            Self::Qcow2 => "qcow2",
            Self::Other => "other",
        }
    }
}

/// What a conversion does with the source's UDIF resources other than
/// the ones the writer regenerates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum ResourcePolicy {
    /// Carry them into a UDIF target. A target that cannot hold them (raw,
    /// sparse, qcow2, UDRW) is refused when there are any, rather than
    /// losing them silently.
    #[default]
    Keep,
    /// Drop them.
    Drop,
}

/// Resource types a re-encoding never carries over: `blkx` is rebuilt,
/// and `cSum` holds checksums of the old encoding. (`plst` is kept.)
#[cfg(feature = "dmg")]
const REGENERATED: [&str; 2] = [crate::block::dmg::BLKX_RESOURCE, "cSum"];

/// `encrcdsa` v2 encryption for a UDIF target.
#[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
#[derive(Clone)]
pub struct DmgEncryption {
    /// Payload cipher.
    pub cipher: crate::block::dmg::encrypted::ContentCipher,
    /// Passphrase protecting the content key.
    pub passphrase: String,
    /// `encrcdsa` payload chunk size. Default 512, as `hdiutil`; larger
    /// chunks amortize the per-chunk IV/AES setup.
    pub chunk_size: u32,
}

#[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
impl DmgEncryption {
    /// AES-128 or AES-256, protected by `passphrase`.
    pub fn new(
        cipher: crate::block::dmg::encrypted::ContentCipher,
        passphrase: impl Into<String>,
    ) -> Self {
        Self {
            cipher,
            passphrase: passphrase.into(),
            chunk_size: crate::block::dmg::encrypted::DEFAULT_CHUNK_SIZE,
        }
    }

    /// Set the `encrcdsa` payload chunk size (a multiple of 16, at most
    /// [`MAX_CHUNK_SIZE`](crate::block::dmg::encrypted::MAX_CHUNK_SIZE)).
    pub fn with_chunk_size(mut self, chunk_size: u32) -> Self {
        self.chunk_size = chunk_size;
        self
    }
}

#[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
impl std::fmt::Debug for DmgEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DmgEncryption")
            .field("cipher", &self.cipher)
            .field("passphrase", &"<redacted>")
            .field("chunk_size", &self.chunk_size)
            .finish()
    }
}

/// One message to the encrypted writer thread: a piece of the UDIF byte
/// stream, or end-of-stream.
#[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
enum SinkMsg {
    Data(Vec<u8>),
    End,
}

/// A `Write + Seek` sink that hands the UDIF byte stream to the writer
/// thread. The writer owns the encryption sink and the output file, so
/// encryption and disk writes overlap the main thread's read/scan/compress
/// pipeline.
#[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
/// Forward-only sink that copies each UDIF write into an owned message for
/// the encryption writer.
///
/// The channel is bounded by **message count**, not bytes: 64 slots, and one
/// message can be as large as a compressed chunk plus UDIF framing. At the
/// maximum chunk/thread settings the queued backlog can therefore reach
/// hundreds of MiB. This is a safety bound, not a memory budget; a byte-based
/// credit scheme would be needed to make the bound tight.
struct ChannelSink {
    tx: std::sync::mpsc::SyncSender<SinkMsg>,
    pos: u64,
}

#[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
impl std::io::Write for ChannelSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tx.send(SinkMsg::Data(buf.to_vec())).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "dmg: encrypted writer stopped",
            )
        })?;
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
impl std::io::Seek for ChannelSink {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match pos {
            std::io::SeekFrom::Current(0) => Ok(self.pos),
            std::io::SeekFrom::Start(n) if n == self.pos => Ok(self.pos),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "dmg: channel sink is forward-only",
            )),
        }
    }

    fn stream_position(&mut self) -> std::io::Result<u64> {
        Ok(self.pos)
    }
}

#[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
impl ChannelSink {
    fn finish(&mut self) -> std::io::Result<()> {
        self.tx.send(SinkMsg::End).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "dmg: encrypted writer stopped",
            )
        })
    }
}

/// Options for [`convert_image`]. Construct with `Default` and assign.
#[derive(Clone)]
#[non_exhaustive]
pub struct ConvertOptions {
    /// Target kind; `None` takes it from the destination's extension
    /// ([`ImageKind::from_extension`]).
    pub target: Option<ImageKind>,
    /// UDIF writer options for a UDIF target. Default: the writer's
    /// defaults (UDZO, CRC-32) with [`UdifLayout::Auto`].
    ///
    /// [`UdifLayout::Auto`]: crate::block::dmg::UdifLayout::Auto
    #[cfg(feature = "dmg-write")]
    pub udif: crate::block::dmg::UdifWriteOptions,
    /// Encrypt a UDIF target with Apple's `encrcdsa` v2 wrapper.
    /// `None` writes an ordinary `.dmg`. A non-UDIF target with encryption
    /// requested is rejected before output creation.
    #[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
    pub dmg_encryption: Option<DmgEncryption>,
    /// For a UDIF source and UDIF target: reproduce the source's `blkx`
    /// map (names, IDs, block descriptors, free-space regions) instead of
    /// `udif.layout`. Default true.
    pub preserve_layout: bool,
    /// The source's other UDIF resources. Default [`ResourcePolicy::Keep`].
    pub resources: ResourcePolicy,
    /// Band size for a sparse target; 0 = hdiutil's default.
    pub sparse_band_size: u64,
    /// Passphrase for an encrypted source (LUKS, encrypted qcow2,
    /// `encrcdsa` `.dmg`). Encrypted sources are refused without one.
    pub password: Option<String>,
    /// What may be dropped from a UDIF source (its code signature, a
    /// legacy resource fork). Default: refuse.
    #[cfg(feature = "dmg")]
    pub policy: crate::block::dmg::UdifRewritePolicy,
}

impl std::fmt::Debug for ConvertOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("ConvertOptions");
        d.field("target", &self.target);
        #[cfg(feature = "dmg-write")]
        d.field("udif", &self.udif);
        #[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
        d.field("dmg_encryption", &self.dmg_encryption);
        d.field("preserve_layout", &self.preserve_layout)
            .field("resources", &self.resources)
            .field("sparse_band_size", &self.sparse_band_size)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"));
        #[cfg(feature = "dmg")]
        d.field("policy", &self.policy);
        d.finish()
    }
}

impl Default for ConvertOptions {
    fn default() -> Self {
        Self {
            target: None,
            #[cfg(feature = "dmg-write")]
            udif: crate::block::dmg::UdifWriteOptions {
                layout: crate::block::dmg::UdifLayout::Auto,
                ..Default::default()
            },
            #[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
            dmg_encryption: None,
            preserve_layout: true,
            resources: ResourcePolicy::Keep,
            sparse_band_size: 0,
            password: None,
            #[cfg(feature = "dmg")]
            policy: Default::default(),
        }
    }
}

/// What [`convert_image`] did.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConvertReport {
    /// The source's kind.
    pub source: ImageKind,
    /// The target's kind.
    pub target: ImageKind,
    /// Logical bytes converted (the source's virtual size).
    pub bytes: u64,
    /// Source resource types dropped (regenerated ones, or all of them
    /// under [`ResourcePolicy::Drop`]).
    pub dropped_resources: Vec<String>,
    /// The UDIF writer's summary, for a UDIF target.
    #[cfg(feature = "dmg-write")]
    pub udif: Option<crate::block::dmg::UdifSummary>,
}

/// Convert the image at `src` into a new image at `dst`, streaming its
/// logical sectors through [`BlockDevice`] — no filesystem is read or
/// rebuilt, so this works the same for partitioned disks, bare volumes
/// and unknown contents.
///
/// Any readable source (raw, UDIF of any readable format — segmented
/// too —, sparse, qcow2, LUKS / encrypted `.dmg` with
/// [`ConvertOptions::password`]) converts to any writable target (raw,
/// UDIF in any writable format, `.sparseimage`, `.sparsebundle`, qcow2).
/// Every logical sector is reproduced; all-zero runs stay holes in sparse
/// targets. From a partitioned UDIF to UDIF the `blkx` map is preserved
/// (see [`ConvertOptions::preserve_layout`]); other resources follow
/// [`ConvertOptions::resources`]. A code-signed source follows
/// [`ConvertOptions::policy`] — the output is never signed.
///
/// The output is built in a hidden sibling of `dst` and renamed over it
/// only once complete: on failure `dst`, if it existed, is untouched.
pub fn convert_image(src: &Path, dst: &Path, opts: &ConvertOptions) -> Result<ConvertReport> {
    if same_file(src, dst) {
        return Err(crate::Error::InvalidArgument(
            "convert: source and destination are the same file".into(),
        ));
    }
    if crate::block::file::is_block_device(dst) {
        return Err(crate::Error::InvalidArgument(
            "convert: the destination must be an image file, not a block device".into(),
        ));
    }
    let target = opts
        .target
        .unwrap_or_else(|| ImageKind::from_extension(dst));
    #[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
    if opts.dmg_encryption.is_some() && target != ImageKind::Udif {
        return Err(crate::Error::InvalidArgument(
            "convert: DMG encryption requires a UDIF target".into(),
        ));
    }
    let source = ImageKind::detect(src)?;
    #[cfg_attr(not(feature = "dmg"), allow(unused_mut))]
    let mut dropped: Vec<String> = Vec::new();

    // The source's UDIF metadata: layout and resources to carry.
    #[cfg(feature = "dmg")]
    let src_info = if source == ImageKind::Udif {
        let info = crate::block::dmg::inspect_udif(src)?;
        opts.policy.check(&info, "converting")?;
        Some(info)
    } else {
        None
    };
    #[cfg(feature = "dmg")]
    let carried: Vec<crate::block::dmg::UdifResource> = match &src_info {
        Some(info) => {
            let mut keep = Vec::new();
            for r in &info.resources.entries {
                let regenerated = REGENERATED.contains(&r.kind.as_str());
                if regenerated || opts.resources == ResourcePolicy::Drop {
                    if !regenerated && !dropped.contains(&r.kind) {
                        dropped.push(r.kind.clone());
                    }
                    continue;
                }
                keep.push(r.clone());
            }
            keep
        }
        None => Vec::new(),
    };
    #[cfg(feature = "dmg")]
    {
        // A target with nowhere to put them must not lose them silently.
        // (`plst` is hdiutil's constant boilerplate, not content.)
        let can_hold = target == ImageKind::Udif && {
            #[cfg(feature = "dmg-write")]
            {
                opts.udif.format != crate::block::dmg::UdifFormat::Udrw
            }
            #[cfg(not(feature = "dmg-write"))]
            {
                false
            }
        };
        let content: Vec<&str> = carried
            .iter()
            .filter(|r| r.kind != "plst")
            .map(|r| r.kind.as_str())
            .collect();
        if !can_hold && !content.is_empty() {
            return Err(crate::Error::InvalidArgument(format!(
                "convert: the source carries UDIF resources ({}) that a {} target cannot hold; \
                 set ResourcePolicy::Drop (CLI: --drop-resources) to discard them",
                content.join(", "),
                target.name()
            )));
        }
    }

    let mut dev = open_source(src, opts.password.as_deref())?;
    let total = dev.total_size();

    #[allow(unused_mut)]
    let mut report = ConvertReport {
        source,
        target,
        bytes: total,
        dropped_resources: dropped,
        #[cfg(feature = "dmg-write")]
        udif: None,
    };

    match target {
        ImageKind::Udif => {
            #[cfg(feature = "dmg-write")]
            {
                use crate::block::dmg::{UdifFormat, write_udif};
                let mut wo = opts.udif.clone();
                #[cfg(feature = "dmg")]
                if let Some(info) = &src_info {
                    if opts.preserve_layout {
                        wo.layout = super::resize::layout_of(info, None)?;
                        if let crate::block::dmg::UdifLayout::WholeDevice = wo.layout
                            && let Some(b) = info.blkx.first()
                            && !b.name.is_empty()
                        {
                            wo.partition_name = b.name.clone();
                        }
                    }
                    if wo.format != UdifFormat::Udrw {
                        let mut res = wo.resources.clone();
                        for r in &carried {
                            if res.get(&r.kind, r.id).is_none() {
                                res.entries.push(r.clone());
                            }
                        }
                        wo.resources = res;
                    }
                }
                wo.validate()?;
                #[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
                let summary = if let Some(enc) = &opts.dmg_encryption {
                    use crate::block::dmg::encrypted::{
                        CreateOptions, EncryptedDmgSink, OsRandom, Protector,
                    };
                    use std::sync::mpsc;
                    write_beside(dst, |tmp| {
                        let f = std::fs::File::create(tmp)?;
                        let copts = CreateOptions {
                            chunk_size: enc.chunk_size,
                            ..CreateOptions::default()
                        };
                        // 64 messages, not 64 chunks of bytes: see
                        // `ChannelSink` for the actual backlog bound.
                        let (tx, rx) = mpsc::sync_channel::<SinkMsg>(64);
                        std::thread::scope(
                            |scope| -> crate::Result<crate::block::dmg::UdifSummary> {
                                let writer = std::thread::Builder::new()
                                    .name("fstool-enc".into())
                                    .spawn_scoped(scope, move || -> crate::Result<()> {
                                        #[cfg(test)]
                                        if enc.passphrase == "__test_panic_writer__" {
                                            panic!("injected encrypted writer panic");
                                        }
                                        let mut sink = EncryptedDmgSink::new(
                                            f,
                                            vec![Protector::Passphrase(&enc.passphrase)],
                                            enc.cipher,
                                            copts,
                                            &mut OsRandom,
                                        )?;
                                        let mut ended = false;
                                        for msg in rx {
                                            match msg {
                                                SinkMsg::Data(buf) => sink.write_all(&buf)?,
                                                SinkMsg::End => {
                                                    ended = true;
                                                    break;
                                                }
                                            }
                                        }
                                        if !ended {
                                            // The main thread failed and dropped
                                            // its sender; leave the partial file
                                            // for `write_beside` to remove.
                                            return Ok(());
                                        }
                                        let (file, _created) = sink.finish(&mut OsRandom)?;
                                        file.sync_all()?;
                                        Ok(())
                                    })
                                    .map_err(|e| {
                                        crate::Error::Io(std::io::Error::other(format!(
                                            "dmg: cannot start encrypted writer: {e}"
                                        )))
                                    })?;
                                // Always join the writer, even when the
                                // producer fails: the scope would otherwise
                                // re-panic the child and bypass the caller's
                                // temporary-file cleanup.
                                let producer =
                                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        let sink = ChannelSink { tx, pos: 0 };
                                        let (mut sink, summary) =
                                            write_udif(dev.as_mut(), sink, &wo)?;
                                        sink.finish()?;
                                        drop(sink);
                                        Ok::<_, crate::Error>(summary)
                                    }))
                                    .unwrap_or_else(|_| {
                                        Err(crate::Error::Io(std::io::Error::other(
                                            "dmg: encrypted conversion panicked",
                                        )))
                                    });
                                let writer_result = writer.join().map_err(|_| {
                                    crate::Error::Io(std::io::Error::other(
                                        "dmg: encrypted writer thread panicked",
                                    ))
                                });
                                match (producer, writer_result) {
                                    // The writer's own error is more specific
                                    // than the BrokenPipe the producer saw
                                    // when the sink went away.
                                    (_, Err(error)) => Err(error),
                                    (_, Ok(Err(error))) => Err(error),
                                    (Err(error), Ok(Ok(()))) => Err(error),
                                    (Ok(summary), Ok(Ok(()))) => Ok(summary),
                                }
                            },
                        )
                    })?
                } else {
                    write_beside(dst, |tmp| {
                        let f = std::fs::File::create(tmp)?;
                        let (f, summary) = write_udif(dev.as_mut(), f, &wo)?;
                        f.sync_all()?;
                        Ok(summary)
                    })?
                };
                #[cfg(not(feature = "dmg-encrypted-write"))]
                let summary = write_beside(dst, |tmp| {
                    let f = std::fs::File::create(tmp)?;
                    let (f, summary) = write_udif(dev.as_mut(), f, &wo)?;
                    f.sync_all()?;
                    Ok(summary)
                })?;
                report.udif = Some(summary);
            }
            #[cfg(not(feature = "dmg-write"))]
            return Err(crate::Error::Unsupported(
                "convert: writing UDIF needs the `dmg-write` feature".into(),
            ));
        }
        ImageKind::Raw | ImageKind::SparseImage | ImageKind::SparseBundle | ImageKind::Qcow2 => {
            let co = crate::block::CreateOpts {
                sparse_band_size: opts.sparse_band_size,
                ..Default::default()
            };
            write_beside(dst, |tmp| {
                let mut out = crate::block::create_image(tmp, total, &co)?;
                copy_sectors(dev.as_mut(), out.as_mut(), total)?;
                out.sync()?;
                Ok(())
            })?;
        }
        ImageKind::Other => {
            return Err(crate::Error::InvalidArgument(
                "convert: ImageKind::Other is not a conversion target".into(),
            ));
        }
    }
    Ok(report)
}

/// Copy `total` bytes from `src` to the fresh, all-zero `dst`, skipping
/// all-zero pieces so sparse targets stay sparse.
pub(crate) fn copy_sectors(
    src: &mut dyn BlockDevice,
    dst: &mut dyn BlockDevice,
    total: u64,
) -> Result<()> {
    let mut buf = vec![0u8; COPY_CHUNK];
    let mut off = 0u64;
    while off < total {
        let n = (total - off).min(buf.len() as u64) as usize;
        src.read_at(off, &mut buf[..n])?;
        if buf[..n].iter().any(|&b| b != 0) {
            dst.write_at(off, &buf[..n])?;
        }
        off += n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn debug_redacts_source_password() {
        let mut opts = ConvertOptions::default();
        assert!(format!("{opts:?}").contains("password: None"));
        opts.password = Some("source-secret-sentinel".into());
        for text in [format!("{opts:?}"), format!("{opts:#?}")] {
            assert!(!text.contains("source-secret-sentinel"));
            assert!(text.contains("<redacted>"));
            assert!(text.contains("target"));
        }
    }

    #[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
    fn encrypted_options() -> ConvertOptions {
        ConvertOptions {
            dmg_encryption: Some(DmgEncryption::new(
                crate::block::dmg::encrypted::ContentCipher::Aes256,
                "output-secret-sentinel",
            )),
            ..ConvertOptions::default()
        }
    }

    #[test]
    #[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
    fn debug_redacts_output_password() {
        let mut opts = encrypted_options();
        opts.password = Some("source-secret-sentinel".into());
        let enc = opts.dmg_encryption.as_ref().unwrap();
        for text in [
            format!("{enc:?}"),
            format!("{enc:#?}"),
            format!("{opts:?}"),
            format!("{opts:#?}"),
        ] {
            assert!(!text.contains("output-secret-sentinel"));
            assert!(!text.contains("source-secret-sentinel"));
            assert!(text.contains("<redacted>"));
            assert!(text.contains("Aes256"));
        }
    }

    #[test]
    #[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
    fn encryption_rejects_non_udif_without_touching_output() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source.raw");
        std::fs::write(&src, [0x42; 512]).unwrap();
        let mut cases = vec![];
        for ext in ["img", "sparseimage", "sparsebundle", "qcow2", "qcow", "q2"] {
            cases.push((None, format!("output.{ext}")));
        }
        for target in [
            ImageKind::Raw,
            ImageKind::SparseImage,
            ImageKind::SparseBundle,
            ImageKind::Qcow2,
            ImageKind::Other,
        ] {
            cases.push((Some(target), "output.dmg".into()));
        }
        for (target, name) in cases {
            let mut opts = encrypted_options();
            opts.target = target;
            let dst = dir.path().join(name);
            for existing in [false, true] {
                if existing {
                    std::fs::write(&dst, b"keep existing").unwrap();
                }
                let error = convert_image(&src, &dst, &opts).unwrap_err();
                assert!(matches!(error, crate::Error::InvalidArgument(_)));
                assert!(error.to_string().contains("requires a UDIF target"));
                if existing {
                    assert_eq!(std::fs::read(&dst).unwrap(), b"keep existing");
                    std::fs::remove_file(&dst).unwrap();
                } else {
                    assert!(!dst.exists());
                }
                assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
            }
        }
    }

    #[test]
    #[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
    fn encrypted_udif_and_plain_raw_remain_supported() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source.raw");
        let data = vec![0x42; 1024];
        std::fs::write(&src, &data).unwrap();
        for (target, name) in [
            (None, "encrypted.dmg"),
            (Some(ImageKind::Udif), "encrypted.img"),
        ] {
            let mut opts = encrypted_options();
            opts.target = target;
            opts.udif.format = crate::block::dmg::UdifFormat::Udro;
            let dst = dir.path().join(name);
            convert_image(&src, &dst, &opts).unwrap();
            assert!(crate::block::dmg::probe_encrypted(&dst).unwrap());
            let mut decoded = open_source(&dst, Some("output-secret-sentinel")).unwrap();
            assert_eq!(decoded.total_size(), data.len() as u64);
            let mut actual = vec![0; data.len()];
            decoded.read_at(0, &mut actual).unwrap();
            assert_eq!(actual, data);

            // `ls` / `cat` / `info` use the read-write opener.
            let mut rw =
                crate::block::open_image_with_password(&dst, Some("output-secret-sentinel"))
                    .unwrap();
            assert_eq!(rw.total_size(), data.len() as u64);
            let mut actual_rw = vec![0; data.len()];
            rw.read_at(0, &mut actual_rw).unwrap();
            assert_eq!(actual_rw, data);
        }
        let dst = dir.path().join("plain.img");
        convert_image(&src, &dst, &ConvertOptions::default()).unwrap();
        assert_eq!(std::fs::read(dst).unwrap(), data);
    }

    #[test]
    #[cfg(all(feature = "dmg-write", feature = "dmg-encrypted-write"))]
    fn encrypted_writer_panic_returns_error_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source.raw");
        std::fs::write(&src, vec![0x42; 1024]).unwrap();
        let dst = dir.path().join("encrypted.dmg");
        let opts = ConvertOptions {
            dmg_encryption: Some(DmgEncryption::new(
                crate::block::dmg::encrypted::ContentCipher::Aes256,
                "__test_panic_writer__",
            )),
            ..ConvertOptions::default()
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let thread_dst = dst.clone();
        let h = std::thread::spawn(move || {
            let result = convert_image(&src, &thread_dst, &opts);
            tx.send(result.is_err()).unwrap();
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(10))
                .expect("encrypted writer panic left conversion blocked"),
            "encrypted writer panic should surface as an error"
        );
        h.join().unwrap();
        assert!(
            !dst.exists(),
            "failed conversion must not publish a destination"
        );
    }
}
