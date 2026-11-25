//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Resume-model acceptance matrix (E4 shared kernel x fault conditions).
//!
//! Included from `scan.rs` tests (`mod resume_matrix`): every inventory
//! scope funnels through this per-object kernel, so a defect here affects
//! every scope. Each cell runs a ROOMY single-pass reference and a SPLIT
//! multi-pass run under the fault, then requires full equivalence of the
//! converged result (tables, interfaces, linkage, finished-scan) plus the
//! condition's discard/revalidate behavior. Cells return `Err` details on
//! mismatch (no early panic), so one run reports the whole table.

use super::*;

type CellResult = Result<String, String>;

fn summarize(outcome: &ScanOutcome) -> String {
    let modules = outcome.modules();
    let tables: usize = modules.iter().map(|m| m.tables.len()).sum();
    let ifaces: usize = modules.iter().map(|m| m.interfaces.len()).sum();
    let finished: Vec<bool> = modules.iter().map(|m| m.tables_scan_finished).collect();
    format!(
        "modules={} tables={tables} ifaces={ifaces} finished={finished:?}",
        modules.len()
    )
}

fn table_shapes(outcome: &ScanOutcome) -> Vec<(u64, usize)> {
    let mut shapes = Vec::new();
    for module in outcome.modules() {
        for table in &module.tables {
            shapes.push((table.address, table.decoded_slot_count()));
        }
    }
    shapes.sort_unstable();
    shapes
}

fn iface_links(outcome: &ScanOutcome) -> Vec<Option<usize>> {
    let mut links = Vec::new();
    for module in outcome.modules() {
        for iface in &module.interfaces {
            links.push(iface.table);
        }
    }
    links.sort_unstable();
    links
}

fn finished_flags(outcome: &ScanOutcome) -> Vec<bool> {
    outcome
        .modules()
        .iter()
        .map(|m| m.tables_scan_finished)
        .collect()
}

/// The single provider module, or a diagnostic `Err` (never a panic).
fn only_module(outcome: &ScanOutcome, what: &str) -> Result<ScannedModule, String> {
    let modules = outcome.modules();
    if modules.len() != 1 {
        return Err(format!(
            "{what}: expected 1 module, got {} ({}) skipped={:?}",
            modules.len(),
            summarize(outcome),
            outcome.skipped()
        ));
    }
    Ok(modules[0].clone())
}

/// Full split-vs-roomy equivalence: same table shapes, same interface
/// linkage, same finished flags.
fn require_equivalent(split: &ScanOutcome, roomy: &ScanOutcome) -> Result<(), String> {
    if table_shapes(split) != table_shapes(roomy) {
        return Err(format!(
            "table shapes differ: split {:?} vs roomy {:?}",
            table_shapes(split),
            table_shapes(roomy)
        ));
    }
    if iface_links(split) != iface_links(roomy) {
        return Err(format!(
            "interface linkage differs: split {:?} vs roomy {:?}",
            iface_links(split),
            iface_links(roomy)
        ));
    }
    if finished_flags(split) != finished_flags(roomy) {
        return Err(format!(
            "finished flags differ: split {:?} vs roomy {:?}",
            finished_flags(split),
            finished_flags(roomy)
        ));
    }
    Ok(())
}

const ROOMY_LIMITS: ScanLimits = ScanLimits {
    per_object_bytes: u64::MAX,
    total_bytes: u64::MAX,
};

/// C1 (negative control): a plain truncated snapshot resumes and converges.
/// The per-object leg covers the first data mapping fully but stops 0x80
/// bytes into the second, before its interface triple.
fn cell_short_read() -> CellResult {
    let mut fixture = BracketFixture::new(8, true);
    let _mounts = pin_compact_mountinfo(&[&fixture.path]);
    let limits = ScanLimits {
        per_object_bytes: 0x2000 + 0x80,
        total_bytes: u64::MAX,
    };
    let (first, carried) = armed_scan_pass(&mut fixture, limits, RetainedFileFacts::default());
    let first = first.map_err(|e| format!("pass 1 failed: {e}"))?;
    if only_module(&first, "pass 1")?.tables_scan_finished {
        return Err("pass 1 grants finished-scan from a truncated snapshot".into());
    }
    if carried.cursor_counts()
        != (CursorCounts {
            cursors: 1,
            unfinished: 1,
        })
    {
        return Err(format!(
            "pass 1 must carry one unfinished cursor, got {:?}",
            carried.cursor_counts()
        ));
    }
    fixture.log.borrow_mut().clear();
    let (second, carried) = armed_scan_pass(&mut fixture, limits, carried);
    let second = second.map_err(|e| format!("pass 2 failed: {e}"))?;
    if !log_reread_at_or_after(&fixture, 0x7000) {
        return Err(format!(
            "pass 2 must re-read the truncated mapping: {:?}",
            fixture.log.borrow()
        ));
    }
    if carried.cursor_counts().unfinished != 0 {
        return Err("fully acquired passes must converge".into());
    }
    let mut roomy_fixture = BracketFixture::new(8, true);
    let (roomy, _) = armed_scan_pass(
        &mut roomy_fixture,
        ROOMY_LIMITS,
        RetainedFileFacts::default(),
    );
    let roomy = roomy.map_err(|e| format!("roomy failed: {e}"))?;
    require_equivalent(&second, &roomy)?;
    Ok(format!("converged {}", summarize(&second)))
}

/// C2: the work budget stops after the sweeps but before the closing
/// bracket validates. The work-starved bracket clears its published
/// rows (flood contract: undecodable modules never publish) but still
/// stages its frontier and rows unvalidated for the next pass; the
/// staged cursor must not claim `complete`: completion needs the
/// bracket. (Composed contract: r4's work-starved clear governs
/// publication, S6's starved-bracket staging governs resume.)
fn cell_budget_stop_before_bracket() -> CellResult {
    // Calibration: work units consumed through the sweeps (maps-B open).
    let mut probe = BracketFixture::new(8, true);
    let (outcome, _) = armed_scan_pass(&mut probe, ROOMY_LIMITS, RetainedFileFacts::default());
    outcome.map_err(|e| format!("calibration failed: {e}"))?;
    let (_, swept_work) = probe
        .before_b
        .ok_or("calibration must reach the maps-B open")?;
    // Fault run: the ceiling dies exactly at the bracket.
    let mut fixture = BracketFixture::new(8, true);
    let mut budget =
        CaptureWorkBudget::new(ROOMY_LIMITS).with_retained_file_facts(RetainedFileFacts::default());
    budget.set_work_ceiling_for_test(swept_work);
    let first = fixture
        .run(&mut budget)
        .map_err(|e| format!("pass 1 failed: {e}"))?;
    if !first.modules().is_empty() {
        return Err(format!(
            "a work-starved bracket clears its published modules: {}",
            summarize(&first)
        ));
    }
    let carried = budget.take_retained_file_facts();
    let cursors = carried.decode_cursors_for_test();
    // The bracket starved before validating anything (all verdicts
    // None): rows and frontiers accumulate (a restart would livelock
    // under tight recurring budgets), but the cursor rides
    // unvalidated and incomplete, so the next use re-proves bytes
    // and re-collects targets instead of replaying.
    if cursors.len() != 1 {
        return Err(format!(
            "a never-validated starve stages one cursor, got {}",
            cursors.len()
        ));
    }
    let staged = &cursors[0].1;
    if staged.complete {
        return Err("staged cursor claims complete without a closing bracket".into());
    }
    if staged.validated {
        return Err("a never-validated starve must not ride validated".into());
    }
    if staged.cached_tables.len() != 1 {
        return Err(format!(
            "a never-validated starve accumulates its decoded rows, got {}",
            staged.cached_tables.len()
        ));
    }
    // Recovery: a healthy pass with the carried frontier converges.
    fixture.maps_reads = 0;
    fixture.log.borrow_mut().clear();
    let (second, carried) = armed_scan_pass(&mut fixture, ROOMY_LIMITS, carried);
    let second = second.map_err(|e| format!("pass 2 failed: {e}"))?;
    if carried.cursor_counts().unfinished != 0 {
        return Err("recovery must converge".into());
    }
    let mut roomy_fixture = BracketFixture::new(8, true);
    let (roomy, _) = armed_scan_pass(
        &mut roomy_fixture,
        ROOMY_LIMITS,
        RetainedFileFacts::default(),
    );
    let roomy = roomy.map_err(|e| format!("roomy failed: {e}"))?;
    require_equivalent(&second, &roomy)?;
    Ok(format!("converged {}", summarize(&second)))
}

/// Write one 2.x 68-slot table at `at` in `mem` (slot 0 own-target,
/// slot 1 NULL, the rest dependency-targets), mirroring the populated
/// fixture's slot pattern.
fn write_table_at(mem: &File, at: u64) {
    use std::os::unix::fs::FileExt as _;
    let mut table = vec![0u8; 69 * 8];
    table[..2].copy_from_slice(&[2, 40]);
    for slot in 0..68 {
        let pointer: u64 = match slot {
            0 => 0x1100,
            1 => 0,
            _ => 0x9100,
        };
        table[(slot + 1) * 8..(slot + 2) * 8].copy_from_slice(&pointer.to_le_bytes());
    }
    mem.write_all_at(&table, at).unwrap();
}

/// C3: a table header sits at the second data mapping's offset zero
/// and the first pass stops 128 bytes into that mapping, so the resume
/// overlap saturates and the second pass re-reads the mapping from byte
/// zero. The re-sweep must re-examine the header; starting past it loses
/// the table yet claims finished-scan. (The per-object cap also covers
/// mountinfo, so the split targets the second mapping, like the plain
/// truncation control.)
fn cell_header_before_cursor() -> CellResult {
    let mut fixture = BracketFixture::new(8, false);
    let _mounts = pin_compact_mountinfo(&[&fixture.path]);
    write_table_at(&fixture.mem, 0x7000);
    // Non-vacuity first: the roomy reference must see the table.
    let mut roomy_probe = BracketFixture::new(8, false);
    write_table_at(&roomy_probe.mem, 0x7000);
    let (roomy, _) = armed_scan_pass(&mut roomy_probe, ROOMY_LIMITS, RetainedFileFacts::default());
    let roomy = roomy.map_err(|e| format!("roomy failed: {e}"))?;
    let roomy_module = only_module(&roomy, "roomy")?;
    if roomy_module.tables.len() != 1 || !roomy_module.tables_scan_finished {
        return Err(format!(
            "roomy must decode the header-at-zero table: {}",
            summarize(&roomy)
        ));
    }
    let limits = ScanLimits {
        per_object_bytes: 0x2000 + 128,
        total_bytes: u64::MAX,
    };
    let (first, carried) = armed_scan_pass(&mut fixture, limits, RetainedFileFacts::default());
    let first = first.map_err(|e| format!("pass 1 failed: {e}"))?;
    if only_module(&first, "pass 1")?.tables_scan_finished {
        return Err("pass 1 grants finished-scan from a short snapshot".into());
    }
    if carried.cursor_counts()
        != (CursorCounts {
            cursors: 1,
            unfinished: 1,
        })
    {
        return Err(format!(
            "pass 1 must carry one unfinished cursor, got {:?}",
            carried.cursor_counts()
        ));
    }
    fixture.maps_reads = 0;
    let (second, carried) = armed_scan_pass(&mut fixture, ROOMY_LIMITS, carried);
    let second = second.map_err(|e| format!("pass 2 failed: {e}"))?;
    if carried.cursor_counts().unfinished != 0 {
        return Err(format!(
            "fully acquired passes must converge: {}",
            summarize(&second)
        ));
    }
    require_equivalent(&second, &roomy)?;
    Ok(format!("converged {}", summarize(&second)))
}

/// A 12 MiB data mapping with a single table at 9 MiB and one interface
/// triple at 4 KiB naming it: the production 8 MiB leg splits them.
struct LateTableFixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    view: ProcessView,
    maps: String,
    mem: File,
    log: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
}

struct LateTableMemory {
    file: File,
    log: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
}

impl ScanMemory for LateTableMemory {
    fn read_memory_at(&self, bytes: &mut [u8], offset: u64) -> std::io::Result<usize> {
        self.log
            .borrow_mut()
            .push(format!("memory {offset:x} {}", bytes.len()));
        use std::os::unix::fs::FileExt as _;
        self.file.read_at(bytes, offset)
    }
}

impl ScanIo for LateTableFixture {
    type Memory = LateTableMemory;
    fn open_maps(
        &mut self,
        _: &ProcessView,
        _: &mut CaptureWorkBudget,
    ) -> std::io::Result<Box<dyn Read>> {
        self.log.borrow_mut().push("maps".into());
        Ok(Box::new(std::io::Cursor::new(
            self.maps.as_bytes().to_vec(),
        )))
    }
    fn open_mem(
        &mut self,
        _: &ProcessView,
        _: &mut CaptureWorkBudget,
    ) -> std::io::Result<LateTableMemory> {
        Ok(LateTableMemory {
            file: self.mem.try_clone()?,
            log: self.log.clone(),
        })
    }
    fn final_generation(
        &mut self,
        view: &ProcessView,
        _: &mut CaptureWorkBudget,
    ) -> Result<(), String> {
        view.run_while_same(|| ())
    }
}

impl LateTableFixture {
    const DATA_BASE: u64 = 0x100_0000;
    const DATA_LEN: u64 = 12 << 20;
    const TABLE_AT: u64 = 9 << 20;
    const TRIPLE_AT: u64 = 0x1000;
    const NAME_AT: u64 = 0x200;

    fn new() -> Self {
        Self::with_layout(Self::DATA_LEN, Self::TABLE_AT, true)
    }

    /// Diagnostic variant: `data_len` zero bytes with one table at
    /// `table_at`, optionally with the early interface triple.
    fn with_layout(data_len: u64, table_at: u64, with_triple: bool) -> Self {
        use std::os::unix::fs::FileExt as _;
        let dir = tempfile::tempdir().unwrap();
        let view = ProcessView::open(ProcessViewId(73), std::process::id()).unwrap();
        let path = dir.path().join("late-provider.so");
        std::fs::write(&path, BracketFixture::minimal_provider_elf(8)).unwrap();
        let file = File::open(&path).unwrap();
        let key = crate::discovery::identity::retained_object_key(
            &view,
            &file,
            &mut CaptureWorkBudget::default(),
        )
        .unwrap();
        let identity = format!(
            "{:x}:{:x} {} {}",
            key.device.major,
            key.device.minor,
            key.inode,
            path.display()
        );
        let maps = format!(
            "1000-2000 r-xp 00000000 {identity}\n\
             9000-a000 r-xp 00000000 08:01 999 /dependency.so\n\
             {:x}-{:x} rw-p 00002000 {identity}\n",
            Self::DATA_BASE,
            Self::DATA_BASE + data_len,
        );
        let mem = tempfile::tempfile().unwrap();
        mem.set_len(Self::DATA_BASE + data_len).unwrap();
        write_table_at(&mem, Self::DATA_BASE + table_at);
        if with_triple {
            mem.write_all_at(
                b"PKCS 11\0PRIVATE_READ_AHEAD_CANARY",
                Self::DATA_BASE + Self::NAME_AT,
            )
            .unwrap();
            for (slot, value) in [
                Self::DATA_BASE + Self::NAME_AT,
                Self::DATA_BASE + table_at,
                0,
            ]
            .into_iter()
            .enumerate()
            {
                mem.write_all_at(
                    &value.to_le_bytes(),
                    Self::DATA_BASE + Self::TRIPLE_AT + (slot * 8) as u64,
                )
                .unwrap();
            }
        }
        Self {
            _dir: dir,
            path,
            view,
            maps,
            mem,
            log: Default::default(),
        }
    }

    fn run(&mut self, budget: &mut CaptureWorkBudget) -> Result<ScanOutcome, String> {
        let view = ProcessView::open(self.view.id(), self.view.pid()).unwrap();
        let hooks = HookRegistry::builtin();
        let hints = [self.path.clone()];
        scan_process_view_with_io(
            &ScanRequest {
                pid: view.pid(),
                hints: &hints,
                hooks: &hooks,
            },
            &view,
            budget,
            self,
        )
    }

    fn pass(
        &mut self,
        limits: ScanLimits,
        carried: RetainedFileFacts,
    ) -> (Result<ScanOutcome, String>, RetainedFileFacts) {
        let mut budget = CaptureWorkBudget::new(limits).with_retained_file_facts(carried);
        let outcome = self.run(&mut budget);
        let carried = budget.take_retained_file_facts();
        (outcome, carried)
    }
}

/// C4: the interface triple sits 4 KiB into the mapping while its table
/// waits at 9 MiB, past the first pass's 8 MiB acquisition. The triple is
/// provisional until the table set is complete: the converged pass must
/// link it, never lose it.
fn cell_interface_before_table() -> CellResult {
    let mut roomy_fixture = LateTableFixture::new();
    let (roomy, _) = roomy_fixture.pass(ROOMY_LIMITS, RetainedFileFacts::default());
    let roomy = roomy.map_err(|e| format!("roomy failed: {e}"))?;
    let roomy_module = only_module(&roomy, "roomy")?;
    if roomy_module.tables.len() != 1 || roomy_module.interfaces.len() != 1 {
        return Err(format!(
            "roomy must link the early triple: {}",
            summarize(&roomy)
        ));
    }
    if roomy_module.interfaces[0].table.is_none() {
        return Err("roomy must link the triple to its table".into());
    }
    let mut fixture = LateTableFixture::new();
    let leg = ScanLimits {
        per_object_bytes: 8 << 20,
        total_bytes: u64::MAX,
    };
    let (first, carried) = fixture.pass(leg, RetainedFileFacts::default());
    let first = first.map_err(|e| format!("pass 1 failed: {e}"))?;
    if only_module(&first, "pass 1")?.tables_scan_finished {
        return Err("pass 1 grants finished-scan below the late table".into());
    }
    if carried.cursor_counts()
        != (CursorCounts {
            cursors: 1,
            unfinished: 1,
        })
    {
        return Err(format!(
            "pass 1 must carry one unfinished cursor, got {:?}",
            carried.cursor_counts()
        ));
    }
    let (second, carried) = fixture.pass(ROOMY_LIMITS, carried);
    let second = second.map_err(|e| format!("pass 2 failed: {e}"))?;
    if carried.cursor_counts().unfinished != 0 {
        return Err(format!(
            "fully acquired passes must converge: {}",
            summarize(&second)
        ));
    }
    require_equivalent(&second, &roomy)?;
    Ok(format!("converged {}", summarize(&second)))
}

/// C5: same-path exec between passes — same PID, same start time, same
/// `/proc/<pid>/exe` link, same mapping layout — but the address space
/// bytes changed. The cursor must not replay the old decode: the pass
/// re-reads and re-decodes.
fn cell_same_path_exec() -> CellResult {
    use std::os::unix::fs::FileExt as _;
    let mut fixture = BracketFixture::new(8, true);
    let (first, carried) =
        armed_scan_pass(&mut fixture, ROOMY_LIMITS, RetainedFileFacts::default());
    let first = first.map_err(|e| format!("pass 1 failed: {e}"))?;
    if only_module(&first, "pass 1")?.tables.len() != 1 {
        return Err(format!(
            "pass 1 must decode the table: {}",
            summarize(&first)
        ));
    }
    // Same-path exec: the layout and image link are unchanged, but the
    // new address space zeroed the old table region.
    fixture
        .mem
        .write_all_at(&vec![0u8; 69 * 8], 0x4800)
        .unwrap();
    fixture.maps_reads = 0;
    // Roomy control over the new bytes.
    let mut control = BracketFixture::new(8, true);
    control
        .mem
        .write_all_at(&vec![0u8; 69 * 8], 0x4800)
        .unwrap();
    let (roomy, _) = armed_scan_pass(&mut control, ROOMY_LIMITS, RetainedFileFacts::default());
    let roomy = roomy.map_err(|e| format!("roomy failed: {e}"))?;
    if !only_module(&roomy, "roomy")?.tables.is_empty() {
        return Err(format!(
            "roomy must see the zeroed bytes: {}",
            summarize(&roomy)
        ));
    }
    fixture.log.borrow_mut().clear();
    let (second, _) = armed_scan_pass(&mut fixture, ROOMY_LIMITS, carried);
    let second = second.map_err(|e| format!("pass 2 failed: {e}"))?;
    if !log_reread_at_or_after(&fixture, 0x4000) {
        return Err(format!(
            "pass 2 must re-read after a same-path exec, not replay: {:?}",
            fixture.log.borrow()
        ));
    }
    require_equivalent(&second, &roomy)?;
    Ok(format!("converged {}", summarize(&second)))
}

/// C6 (negative control): the provider file is replaced between passes
/// (same path and inode, new size and ctime, so a new pin). The stale
/// cursor must miss and the pass must scan fresh — never replay, never
/// merge identities.
fn cell_file_replaced() -> CellResult {
    let mut fixture = BracketFixture::new(8, true);
    let (first, carried) =
        armed_scan_pass(&mut fixture, ROOMY_LIMITS, RetainedFileFacts::default());
    let first = first.map_err(|e| format!("pass 1 failed: {e}"))?;
    if only_module(&first, "pass 1")?.tables.len() != 1 {
        return Err(format!(
            "pass 1 must decode the table: {}",
            summarize(&first)
        ));
    }
    // Replace the file in place: same inode, new bytes and pin.
    let mut elf = BracketFixture::minimal_provider_elf(8);
    elf.extend_from_slice(&[0u8; 512]);
    std::fs::write(&fixture.path, &elf).unwrap();
    fixture.maps_reads = 0;
    fixture.log.borrow_mut().clear();
    let (second, carried) = armed_scan_pass(&mut fixture, ROOMY_LIMITS, carried);
    let second = second.map_err(|e| format!("pass 2 failed: {e}"))?;
    if !log_reread_at_or_after(&fixture, 0x4000) {
        return Err(format!(
            "pass 2 must re-read after the file replacement: {:?}",
            fixture.log.borrow()
        ));
    }
    let cursors = carried.decode_cursors_for_test();
    if cursors.len() != 1 {
        return Err(format!(
            "exactly the fresh cursor carries, got {}",
            cursors.len()
        ));
    }
    let file = File::open(&fixture.path).unwrap();
    let current_pin = pin_of(&file).map_err(|e| format!("pin read failed: {e}"))?;
    if cursors[0].0.file.pin != current_pin {
        return Err("the carried cursor must name the replacement pin".into());
    }
    // The process memory still holds the old bytes (mmap does not follow
    // an in-place rewrite), so the fresh scan decodes the same table.
    let mut control = BracketFixture::new(8, true);
    let (roomy, _) = armed_scan_pass(&mut control, ROOMY_LIMITS, RetainedFileFacts::default());
    let roomy = roomy.map_err(|e| format!("roomy failed: {e}"))?;
    require_equivalent(&second, &roomy)?;
    Ok(format!("converged {}", summarize(&second)))
}

/// C7: a tight recurring work budget over a table-at-end blob must
/// still converge: every pass advances its frontier (never re-walks
/// proven words), starved passes accumulate unvalidated rows, and the
/// run converges to the roomy result. Guards the resume-livelock
/// class (restart-on-starve, prefix re-sweep).
fn cell_tight_recurring_budget() -> CellResult {
    let mut fixture = LateTableFixture::with_layout(300 << 10, (300 << 10) - 2048, false);
    let mut carried = RetainedFileFacts::default();
    let mut last_tables_word = 0u64;
    let mut advanced = false;
    for pass in 0..20 {
        let mut budget = CaptureWorkBudget::new(ROOMY_LIMITS).with_retained_file_facts(carried);
        budget.set_work_ceiling_for_test(5000);
        let outcome = fixture
            .run(&mut budget)
            .map_err(|e| format!("pass {pass} failed: {e}"))?;
        carried = budget.take_retained_file_facts();
        let cursors = carried.decode_cursors_for_test();
        if cursors.len() != 1 {
            return Err(format!(
                "pass {pass}: expected one cursor, got {}",
                cursors.len()
            ));
        }
        let cursor = &cursors[0].1;
        if cursor.tables.word < last_tables_word && cursor.tables.snapshot == 0 {
            return Err(format!("pass {pass}: table frontier moved backward"));
        }
        if cursor.tables.word > last_tables_word {
            advanced = true;
        }
        last_tables_word = cursor.tables.word;
        // Convergence is the cursor's: work-starved passes clear their
        // publication (flood contract) but stage frontiers, so modules
        // appear only once a pass completes. A complete validated
        // cursor always rides a published module (the bracket passed).
        if cursor.complete && cursor.validated {
            if only_module(&outcome, &format!("pass {pass}"))?.tables.len() != 1 {
                return Err(format!(
                    "a complete validated cursor rides one decoded table: {}",
                    summarize(&outcome)
                ));
            }
            let mut roomy_fixture =
                LateTableFixture::with_layout(300 << 10, (300 << 10) - 2048, false);
            let (roomy, _) = roomy_fixture.pass(ROOMY_LIMITS, RetainedFileFacts::default());
            let roomy = roomy.map_err(|e| format!("roomy failed: {e}"))?;
            require_equivalent(&outcome, &roomy)?;
            if !advanced {
                return Err("convergence without frontier advance is vacuous".into());
            }
            return Ok(format!("converged at pass {pass}: {}", summarize(&outcome)));
        }
    }
    Err("tight recurring budget never converged in 20 passes".into())
}

type MatrixCell = (&'static str, fn() -> CellResult);

#[test]
fn resume_matrix_split_matches_roomy_and_discards_on_identity_change() {
    let cells: [MatrixCell; 7] = [
        ("short_read", cell_short_read),
        (
            "budget_stop_before_bracket",
            cell_budget_stop_before_bracket,
        ),
        ("header_before_cursor", cell_header_before_cursor),
        ("interface_before_table", cell_interface_before_table),
        ("same_path_exec", cell_same_path_exec),
        ("file_replaced", cell_file_replaced),
        ("tight_recurring_budget", cell_tight_recurring_budget),
    ];
    let mut failures = 0u32;
    let mut report = String::from("resume matrix (E4 shared kernel):\n");
    for (name, cell) in cells {
        match cell() {
            Ok(summary) => report.push_str(&format!("  PASS {name}: {summary}\n")),
            Err(details) => {
                failures += 1;
                report.push_str(&format!("  FAIL {name}: {details}\n"));
            }
        }
    }
    assert_eq!(failures, 0, "{report}");
}

/// A fixture whose view uses the pidfd pin, or the `/proc` start-time
/// fallback pin when `fallback` is set.
fn bracket_fixture_on_pin(fallback: bool) -> BracketFixture {
    let mut fixture = BracketFixture::new(8, true);
    if fallback {
        fixture.view = crate::process::start_time_pinned_process_view_for_test(
            ProcessViewId(71),
            std::process::id(),
        )
        .unwrap();
    }
    fixture
}

/// Generation probes the closing bracket issued after `final_generation`
/// returned in the last fixture run.
fn closing_probes_since_final_generation() -> u64 {
    let mark = FINAL_GENERATION_PROBES
        .with(std::cell::Cell::take)
        .expect("the run reached the closing bracket");
    crate::process::generation_probe_test::count() - mark
}

/// A budget-stopped closing bracket buys at most one generation probe,
/// on both pin types: the work-starved bracket (C2: the work ceiling
/// dies exactly at the bracket) proves its live pin once for staging and
/// retirement together, and still stages its frontier; the deadline-
/// starved keep arm probes at most once.
#[test]
fn stopped_closing_bracket_probes_its_generation_at_most_once() {
    for fallback in [false, true] {
        let mut probe = bracket_fixture_on_pin(fallback);
        let (outcome, _) = armed_scan_pass(&mut probe, ROOMY_LIMITS, RetainedFileFacts::default());
        outcome.expect("calibration");
        let (_, swept_work) = probe.before_b.expect("calibration reaches maps B");
        let mut fixture = bracket_fixture_on_pin(fallback);
        let mut budget = CaptureWorkBudget::new(ROOMY_LIMITS)
            .with_retained_file_facts(RetainedFileFacts::default());
        budget.set_work_ceiling_for_test(swept_work);
        FINAL_GENERATION_PROBES.with(|mark| mark.set(None));
        let first = fixture.run(&mut budget).expect("pass 1");
        assert!(
            first.modules().is_empty(),
            "the work-starved bracket clears"
        );
        assert_eq!(
            closing_probes_since_final_generation(),
            1,
            "fallback {fallback}: one closing probe decides staging and retirement"
        );
        let carried = budget.take_retained_file_facts();
        assert_eq!(
            carried.decode_cursors_for_test().len(),
            1,
            "fallback {fallback}: the admitted probe still stages the frontier"
        );

        let mut keep = bracket_fixture_on_pin(fallback);
        keep.expire_at_b = true;
        let mut budget = CaptureWorkBudget::new(ROOMY_LIMITS)
            .with_retained_file_facts(RetainedFileFacts::default());
        budget.set_deadline(Some(u64::MAX));
        FINAL_GENERATION_PROBES.with(|mark| mark.set(None));
        let kept = keep.run(&mut budget).expect("deadline pass");
        assert_eq!(
            kept.modules().len(),
            1,
            "the deadline-starved bracket keeps"
        );
        assert!(
            closing_probes_since_final_generation() <= 1,
            "fallback {fallback}: the keep arm probes at most once"
        );
    }
}

/// A C2 first pass on a fresh fixture: the work ceiling dies exactly at
/// the closing bracket, which stages one unvalidated, unfinished cursor.
/// Returns the fixture (reset for its next pass) and the carried facts.
fn c2_staged_cursor() -> (BracketFixture, RetainedFileFacts) {
    c2_staged_cursor_with(|| BracketFixture::new(8, true))
}

/// [`c2_staged_cursor`] on the fixture `make` builds.
fn c2_staged_cursor_with(make: fn() -> BracketFixture) -> (BracketFixture, RetainedFileFacts) {
    let mut probe = make();
    let (outcome, _) = armed_scan_pass(&mut probe, ROOMY_LIMITS, RetainedFileFacts::default());
    outcome.expect("calibration");
    let (_, swept_work) = probe.before_b.expect("calibration reaches maps B");
    let mut fixture = make();
    let mut budget =
        CaptureWorkBudget::new(ROOMY_LIMITS).with_retained_file_facts(RetainedFileFacts::default());
    budget.set_work_ceiling_for_test(swept_work);
    fixture.run(&mut budget).expect("pass 1");
    let carried = budget.take_retained_file_facts();
    assert_eq!(
        carried.decode_cursors_for_test().len(),
        1,
        "C2 stages one cursor"
    );
    fixture.maps_reads = 0;
    fixture.log.borrow_mut().clear();
    (fixture, carried)
}

/// A roomy budget carrying `carried`, whose shared collection work
/// admits exactly `credits` units.
fn credited_roomy_budget(
    carried: RetainedFileFacts,
    credits: u64,
) -> (
    CaptureWorkBudget,
    std::sync::Arc<std::sync::atomic::AtomicU64>,
) {
    let spent = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counted = spent.clone();
    let mut budget = CaptureWorkBudget::new(ROOMY_LIMITS).with_retained_file_facts(carried);
    budget.set_collection_work(CollectionWork::new(move |units| {
        use std::sync::atomic::Ordering;
        let used = counted.load(Ordering::SeqCst);
        if used.saturating_add(units) > credits {
            return false;
        }
        counted.store(used + units, Ordering::SeqCst);
        true
    }));
    (budget, spent)
}

/// A failed generation check that proves nothing (a non-budget
/// `final_generation` error over a live pin, the shape of a denied
/// mount-namespace read) never retires the pid's carried cursors:
/// retirement needs a proved exit or reuse.
#[test]
fn unproven_generation_failure_keeps_carried_cursors() {
    let (mut fixture, carried) = c2_staged_cursor();
    fixture.fail_generation = true;
    let (_, after) = armed_scan_pass(&mut fixture, ROOMY_LIMITS, carried);
    assert!(
        !after.decode_cursors_for_test().is_empty(),
        "an unproven generation failure keeps the carried cursor"
    );
}

/// A carried cursor survives every shared-credit count on its resume
/// pass: a refused replay or re-proof read (no bytes checked) never
/// discards it, and with room the pass resumes it to completion.
#[test]
fn refused_replay_read_keeps_the_carried_cursor() {
    // The units a roomy resume pass spends, so the sweep covers every
    // stop point up to and past completion.
    let needed = {
        let (mut fixture, carried) = c2_staged_cursor();
        let (mut budget, spent) = credited_roomy_budget(carried, u64::MAX);
        fixture.run(&mut budget).expect("roomy resume pass");
        let after = budget.take_retained_file_facts();
        assert!(
            after
                .decode_cursors_for_test()
                .iter()
                .all(|(_, cursor)| cursor.complete),
            "the roomy resume pass completes: {:?}",
            after.cursor_counts()
        );
        spent.load(std::sync::atomic::Ordering::SeqCst)
    };
    let mut converged = false;
    for credits in 0..=needed + 1 {
        let (mut fixture, carried) = c2_staged_cursor();
        let (mut budget, _) = credited_roomy_budget(carried, credits);
        let _ = fixture.run(&mut budget);
        let after = budget.take_retained_file_facts();
        let cursors = after.decode_cursors_for_test();
        assert!(
            !cursors.is_empty(),
            "credits {credits}: the carried cursor was discarded without a proof"
        );
        converged |= cursors.iter().all(|(_, cursor)| cursor.complete);
    }
    assert!(converged, "with enough credit the resumed pass completes");
}

/// A roomy first pass on a fresh fixture: one complete, validated
/// cursor. Returns the fixture (reset for its next pass) and the facts.
fn roomy_complete_cursor() -> (BracketFixture, RetainedFileFacts) {
    roomy_complete_cursor_with(|| BracketFixture::new(8, true))
}

/// [`roomy_complete_cursor`] on the fixture `make` builds.
fn roomy_complete_cursor_with(make: fn() -> BracketFixture) -> (BracketFixture, RetainedFileFacts) {
    let mut fixture = make();
    let (outcome, carried) =
        armed_scan_pass(&mut fixture, ROOMY_LIMITS, RetainedFileFacts::default());
    outcome.expect("roomy pass");
    let cursors = carried.decode_cursors_for_test();
    assert_eq!(cursors.len(), 1, "a roomy pass keeps one cursor");
    assert!(cursors[0].1.complete, "a roomy pass completes its cursor");
    fixture.maps_reads = 0;
    fixture.log.borrow_mut().clear();
    (fixture, carried)
}

/// A replay read that cannot complete checks no bytes: after a short
/// read (memory truncated below the cached row) or a failed read (a
/// descriptor that cannot read), the carried cursor stays with its row,
/// on the unvalidated proof path (C2 staging) and on the
/// validated-complete replay alike.
#[test]
fn inconclusive_replay_reads_keep_the_carried_cursor() {
    for complete in [false, true] {
        for fault in ["short read", "failed read"] {
            let (mut fixture, carried) = if complete {
                roomy_complete_cursor()
            } else {
                c2_staged_cursor()
            };
            let before = carried.decode_cursors_for_test();
            assert_eq!(before.len(), 1);
            let (key, cursor) = before[0].clone();
            assert_eq!(cursor.complete, complete);
            let row = cursor
                .cached_tables
                .first()
                .expect("the carried cursor holds a decoded row")
                .address;
            if fault == "short read" {
                fixture.mem.set_len(row + 8).unwrap();
            } else {
                fixture.mem = std::fs::OpenOptions::new()
                    .write(true)
                    .open(format!(
                        "/proc/self/fd/{}",
                        std::os::fd::AsRawFd::as_raw_fd(&fixture.mem)
                    ))
                    .unwrap();
            }
            let (_, after) = armed_scan_pass(&mut fixture, ROOMY_LIMITS, carried);
            let kept = after
                .decode_cursors_for_test()
                .into_iter()
                .find(|(held, _)| *held == key)
                .unwrap_or_else(|| {
                    panic!("complete {complete}, {fault}: the carried cursor was discarded without a byte check")
                });
            assert!(
                kept.1
                    .cached_tables
                    .iter()
                    .any(|table| table.address == row),
                "complete {complete}, {fault}: the carried cursor keeps its row"
            );
        }
    }
}

/// Where [`v32_prefix_fixture`] puts its table: the 68-slot legacy
/// prefix (header word plus 68 pointers) ends at the data mapping end.
const V32_TABLE: u64 = 0x6000 - 69 * 8;

/// The bracket fixture with its table replaced by a 3.2-labelled one
/// at the end of the readable data mapping: the legacy prefix is
/// readable and the declared 3.2 extension falls into unmapped memory.
fn v32_prefix_fixture() -> BracketFixture {
    use std::os::unix::fs::FileExt as _;
    let mut fixture = BracketFixture::new(8, true);
    fixture.mem.write_all_at(&[0u8; 69 * 8], 0x4800).unwrap();
    let mut table = vec![0u8; 69 * 8];
    table[..2].copy_from_slice(&[3, 2]);
    for slot in 0..68 {
        let pointer: u64 = match slot {
            0 => 0x1100,
            1 => 0,
            _ => 0x9100,
        };
        table[(slot + 1) * 8..(slot + 2) * 8].copy_from_slice(&pointer.to_le_bytes());
    }
    fixture.mem.write_all_at(&table, V32_TABLE).unwrap();
    fixture
        .mem
        .write_all_at(&V32_TABLE.to_le_bytes(), 0x7100 + 8)
        .unwrap();
    fixture.hole = Some((0x6000, 0x7000));
    fixture
}

/// The cached 3.2 row a staged or completed cursor carries.
fn v32_cached_row(carried: &RetainedFileFacts) -> (DecodeCursorKey, ScannedTable) {
    let cursors = carried.decode_cursors_for_test();
    assert_eq!(cursors.len(), 1, "one carried cursor");
    let (key, cursor) = cursors[0].clone();
    let row = cursor
        .cached_tables
        .iter()
        .find(|table| table.address == V32_TABLE)
        .cloned()
        .expect("the cursor carries the 3.2 row");
    assert_eq!(
        (row.version, row.walk, row.decoded_slot_count()),
        ((3, 2), "known_prefix", 68),
        "the fresh decode keeps the readable legacy prefix"
    );
    (key, row)
}

/// A 3.2-labelled table whose 68-slot legacy prefix is readable and
/// whose declared extension is unmapped replays its proven prefix on
/// every pass: the replay reads the declared extent, meets the hole,
/// re-proves the complete prefix and publishes it as `known_prefix`
/// (the extension stays an unproven gap), with the cursor kept, on the
/// unvalidated (C2 staging) and the validated-complete replay alike.
/// It matches a fresh roomy decode of the same memory. Controls: a
/// changed prefix slot rescans to the fresh truth, and a hole inside
/// the prefix (a short read below the proven span) keeps the cursor
/// and names the object as waiting.
#[test]
fn readable_v32_prefix_with_unmapped_extension_replays_the_prefix() {
    use std::os::unix::fs::FileExt as _;
    let fresh = {
        let mut fixture = v32_prefix_fixture();
        let (outcome, _) =
            armed_scan_pass(&mut fixture, ROOMY_LIMITS, RetainedFileFacts::default());
        outcome.expect("fresh roomy pass")
    };
    for complete in [false, true] {
        let staged = || {
            if complete {
                roomy_complete_cursor_with(v32_prefix_fixture)
            } else {
                c2_staged_cursor_with(v32_prefix_fixture)
            }
        };

        // Unchanged memory: the prefix replays.
        let (mut fixture, carried) = staged();
        let (key, row) = v32_cached_row(&carried);
        let (outcome, after) = armed_scan_pass(&mut fixture, ROOMY_LIMITS, carried);
        let outcome = outcome.expect("resume pass");
        let replayed = fixture.log.borrow().iter().any(|event| {
            event
                .strip_prefix(&format!("memory {V32_TABLE:x} "))
                .and_then(|len| len.parse::<usize>().ok())
                .is_some_and(|len| len > 69 * 8)
        });
        assert!(
            replayed,
            "complete {complete}: the replay reads the declared extent: {:?}",
            fixture.log.borrow()
        );
        assert!(
            outcome
                .skipped()
                .iter()
                .all(|skip| skip.reason != REPLAY_UNPROVEN_REASON),
            "complete {complete}: a readable prefix is never skipped: {:?}",
            outcome.skipped()
        );
        let module = only_module(&outcome, "replayed prefix").unwrap();
        let published = module
            .tables
            .iter()
            .find(|table| table.address == V32_TABLE)
            .unwrap_or_else(|| panic!("complete {complete}: the proven prefix is published"));
        assert_eq!(
            (
                published.version,
                published.walk,
                published.decoded_slot_count()
            ),
            ((3, 2), "known_prefix", 68),
            "complete {complete}: the prefix publishes with the extension gap named"
        );
        assert_eq!(published.entries, row.entries);
        require_equivalent(&outcome, &fresh)
            .unwrap_or_else(|error| panic!("complete {complete}: {error}"));
        let kept = after
            .decode_cursors_for_test()
            .into_iter()
            .find(|(held, _)| *held == key)
            .unwrap_or_else(|| panic!("complete {complete}: the cursor is kept"));
        assert!(
            kept.1.complete
                && kept
                    .1
                    .cached_tables
                    .iter()
                    .any(|table| table.address == V32_TABLE),
            "complete {complete}: the cursor completes with its row"
        );

        // Control: a changed prefix slot rescans to the fresh truth.
        let (mut fixture, carried) = staged();
        let (_, row) = v32_cached_row(&carried);
        fixture
            .mem
            .write_all_at(&0x1100u64.to_le_bytes(), V32_TABLE + 3 * 8)
            .unwrap();
        let (outcome, _) = armed_scan_pass(&mut fixture, ROOMY_LIMITS, carried);
        let outcome = outcome.expect("changed-prefix pass");
        let module = only_module(&outcome, "changed prefix").unwrap();
        let published = module
            .tables
            .iter()
            .find(|table| table.address == V32_TABLE)
            .unwrap_or_else(|| panic!("complete {complete}: the changed prefix rescans"));
        assert_eq!(published.walk, "known_prefix");
        assert_ne!(
            published.entries, row.entries,
            "complete {complete}: the changed slot is the fresh truth"
        );

        // Control: a hole inside the prefix checks no complete span.
        let (mut fixture, carried) = staged();
        let (key, _) = v32_cached_row(&carried);
        fixture.hole = Some((V32_TABLE + 100, 0x7000));
        let (outcome, after) = armed_scan_pass(&mut fixture, ROOMY_LIMITS, carried);
        let outcome = outcome.expect("short-prefix pass");
        assert!(
            outcome
                .skipped()
                .iter()
                .any(|skip| skip.reason == REPLAY_UNPROVEN_REASON),
            "complete {complete}: a short read inside the prefix waits, named: {:?}",
            outcome.skipped()
        );
        assert!(
            after
                .decode_cursors_for_test()
                .iter()
                .any(|(held, _)| *held == key),
            "complete {complete}: a short read inside the prefix keeps the cursor"
        );
    }
}

/// Where [`v32_full_fixture`] puts its table: a complete 3.2 row inside
/// the data mapping.
const V32_FULL_TABLE: u64 = 0x4800;

/// The bracket fixture with its table replaced by a complete 3.2 row
/// (header word plus 104 pointers), its whole declared extent readable.
fn v32_full_fixture() -> BracketFixture {
    use std::os::unix::fs::FileExt as _;
    let fixture = BracketFixture::new(8, true);
    let mut table = vec![0u8; 105 * 8];
    table[..2].copy_from_slice(&[3, 2]);
    for slot in 0..104 {
        let pointer: u64 = match slot {
            0 => 0x1100,
            1 => 0,
            _ => 0x9100,
        };
        table[(slot + 1) * 8..(slot + 2) * 8].copy_from_slice(&pointer.to_le_bytes());
    }
    fixture.mem.write_all_at(&table, V32_FULL_TABLE).unwrap();
    fixture
}

/// A cached full 3.2 row whose 68-slot prefix is re-read unchanged but
/// whose tail is unreadable proves nothing about its tail entries: the
/// replay waits, named, and the carried cursor keeps its rows and its
/// frontier exactly, on the unvalidated (C2 staging) and the
/// validated-complete replay alike. Control: with the tail readable the
/// same cursor replays.
#[test]
fn unreadable_tail_of_a_full_v32_row_keeps_the_cursor_unchanged() {
    for complete in [false, true] {
        let staged = || {
            if complete {
                roomy_complete_cursor_with(v32_full_fixture)
            } else {
                c2_staged_cursor_with(v32_full_fixture)
            }
        };
        let (mut fixture, carried) = staged();
        let cursors = carried.decode_cursors_for_test();
        assert_eq!(cursors.len(), 1);
        let (key, cursor) = cursors[0].clone();
        let row = cursor
            .cached_tables
            .iter()
            .find(|table| table.address == V32_FULL_TABLE)
            .cloned()
            .expect("the cursor carries the full 3.2 row");
        assert!(
            row.version == (3, 2) && row.decoded_slot_count() > LEGACY_PREFIX_SLOTS,
            "calibration: a full 3.2 row is cached ({:?}, {} slots)",
            row.version,
            row.decoded_slot_count()
        );
        fixture.hole = Some((V32_FULL_TABLE + 69 * 8, 0x7000));
        let (outcome, after) = armed_scan_pass(&mut fixture, ROOMY_LIMITS, carried);
        let outcome = outcome.expect("unreadable-tail pass");
        assert!(
            outcome
                .skipped()
                .iter()
                .any(|skip| skip.reason == REPLAY_UNPROVEN_REASON),
            "complete {complete}: the unread tail waits, named: {:?}",
            outcome.skipped()
        );
        let kept = after
            .decode_cursors_for_test()
            .into_iter()
            .find(|(held, _)| *held == key)
            .unwrap_or_else(|| panic!("complete {complete}: the cursor is kept"))
            .1;
        assert_eq!(
            kept.cached_tables, cursor.cached_tables,
            "complete {complete}: the cached rows are unchanged"
        );
        assert_eq!(
            (kept.tables, kept.interfaces, kept.complete, kept.validated),
            (
                cursor.tables,
                cursor.interfaces,
                cursor.complete,
                cursor.validated
            ),
            "complete {complete}: the frontier is unchanged"
        );

        // Control: the readable tail replays the same cursor.
        let (mut fixture, carried) = staged();
        let (outcome, _) = armed_scan_pass(&mut fixture, ROOMY_LIMITS, carried);
        let outcome = outcome.expect("readable-tail pass");
        assert!(
            outcome
                .skipped()
                .iter()
                .all(|skip| skip.reason != REPLAY_UNPROVEN_REASON),
            "complete {complete}: a readable row replays: {:?}",
            outcome.skipped()
        );
    }
}

/// A replay read that returns fewer bytes than the legacy prefix still
/// charges every byte the kernel returned before it is classified.
#[test]
fn a_short_replay_read_charges_its_returned_bytes() {
    let (fixture, carried) = roomy_complete_cursor_with(v32_prefix_fixture);
    let (_, row) = v32_cached_row(&carried);
    let memory = BracketMemory {
        file: fixture.mem.try_clone().unwrap(),
        log: Default::default(),
        hole: Some((V32_TABLE + 100, 0x7000)),
    };
    let mut budget = CaptureWorkBudget::new(ROOMY_LIMITS);
    let before = budget.attempted_io_bytes();
    let read = reread_table_extent(LinuxLayout::Lp64, &row, &memory, &mut budget);
    assert!(
        matches!(read, ReplayRead::Unavailable),
        "a short read is unavailable"
    );
    assert_eq!(
        budget.attempted_io_bytes() - before,
        100,
        "the 100 returned bytes are charged"
    );
}
