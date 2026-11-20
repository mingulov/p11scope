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
    let limits = ScanLimits {
        per_object_bytes: 0x2000 + 0x80,
        total_bytes: u64::MAX,
    };
    let (first, carried) = armed_scan_pass(&mut fixture, limits, RetainedFileFacts::default());
    let first = first.map_err(|e| format!("pass 1 failed: {e}"))?;
    if only_module(&first, "pass 1")?.tables_scan_finished {
        return Err("pass 1 grants finished-scan from a truncated snapshot".into());
    }
    if carried.cursor_counts() != (1, 1) {
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
    if carried.cursor_counts().1 != 0 {
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
    if carried.cursor_counts().1 != 0 {
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
    if carried.cursor_counts() != (1, 1) {
        return Err(format!(
            "pass 1 must carry one unfinished cursor, got {:?}",
            carried.cursor_counts()
        ));
    }
    fixture.maps_reads = 0;
    let (second, carried) = armed_scan_pass(&mut fixture, ROOMY_LIMITS, carried);
    let second = second.map_err(|e| format!("pass 2 failed: {e}"))?;
    if carried.cursor_counts().1 != 0 {
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
    if carried.cursor_counts() != (1, 1) {
        return Err(format!(
            "pass 1 must carry one unfinished cursor, got {:?}",
            carried.cursor_counts()
        ));
    }
    let (second, carried) = fixture.pass(ROOMY_LIMITS, carried);
    let second = second.map_err(|e| format!("pass 2 failed: {e}"))?;
    if carried.cursor_counts().1 != 0 {
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
        if only_module(&outcome, &format!("pass {pass}"))?.tables.len() == 1
            && cursor.complete
            && cursor.validated
        {
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
