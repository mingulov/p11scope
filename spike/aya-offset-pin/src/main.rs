//! Attach the `pin` uprobe at a caller-supplied offset, run the target once,
//! print the hit count. Exit 0 iff hits == expected. Exit 3 on attach error.

use aya::maps::Array;
use aya::programs::UProbe;
use aya::programs::uprobe::{UProbeAttachLocation, UProbeScope};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, obj, target, off_hex, expect] = &args[..] else {
        eprintln!("usage: aya-offset-pin <ebpf.o> <target-exe> <0xoffset> <expected-calls>");
        std::process::exit(2);
    };
    let offset = u64::from_str_radix(off_hex.trim_start_matches("0x"), 16).expect("hex offset");
    let mut ebpf = aya::Ebpf::load(&std::fs::read(obj).expect("read ebpf object")).expect("load ebpf");
    let prog: &mut UProbe = ebpf
        .program_mut("pin")
        .expect("program 'pin'")
        .try_into()
        .expect("uprobe program");
    prog.load().expect("kernel load");
    if let Err(e) = prog.attach(
        UProbeAttachLocation::AbsoluteOffset(offset),
        target,
        UProbeScope::AllProcesses,
    ) {
        println!("attach_error={e}");
        std::process::exit(3);
    }
    let status = std::process::Command::new(target).status().expect("run target");
    assert!(status.success(), "target exited nonzero");
    let hits: Array<_, u64> = Array::try_from(ebpf.map("HITS").expect("map HITS")).expect("array");
    let n = hits.get(&0, 0).expect("read map");
    println!("hits={n} expected={expect}");
    std::process::exit(if n.to_string() == *expect { 0 } else { 1 });
}
