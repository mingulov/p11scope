//! SPDX-License-Identifier: GPL-3.0-or-later
//! Unprivileged JSON adapter for system-scope-measure.sh's opt-in component model.
//! Build this example with the same feature profile as the measured observer.

use p11scope::capacity::DetailedResources;
use serde_json::json;
use std::io::Write;

fn run() -> Result<(), String> {
    let compiled_profile = if cfg!(feature = "wide-detailed-2112") {
        "wide-detailed-2112"
    } else {
        "default"
    };
    let mut possible_cpus = None;
    let mut requested_profile = None;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--possible-cpus" if possible_cpus.is_none() => {
                possible_cpus = Some(
                    args.next()
                        .ok_or("--possible-cpus requires a count")?
                        .parse::<u64>()
                        .map_err(|_| "--possible-cpus requires a u64 count")?,
                );
            }
            "--profile" if requested_profile.is_none() => {
                requested_profile = Some(args.next().ok_or("--profile requires a name")?);
            }
            _ => return Err(format!("unknown or repeated argument: {argument}")),
        }
    }
    let requested_profile = requested_profile.ok_or("--profile is required")?;
    if requested_profile != compiled_profile {
        return Err(format!(
            "requested profile {requested_profile} differs from compiled profile {compiled_profile}"
        ));
    }
    let calculation =
        DetailedResources::compiled(possible_cpus.ok_or("--possible-cpus is required")?)?;
    let mut document = serde_json::to_value(calculation).map_err(|error| error.to_string())?;
    document["schema"] = json!("p11scope-detailed-resources-v1");
    document["profile"] = json!(compiled_profile);
    document["accounting"] =
        json!("component payload model; not RSS, exact kernel memory or an FD budget");
    document["omitted_costs"] = json!([
        "map allocation overhead",
        "identity and task storage",
        "other maps and rings",
        "programs and dynamic attachments",
        "userspace state and transient allocation"
    ]);
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &document).map_err(|error| error.to_string())?;
    writeln!(output).map_err(|error| error.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("detailed resources: {error}");
        std::process::exit(2);
    }
}
