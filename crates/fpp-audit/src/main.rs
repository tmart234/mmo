//! fpp-audit: audits evidence bundles (see the library's docs).
//!
//!     fpp-audit <bundle.fppb>...
//!
//! Prints each bundle's findings and notes; with several bundles of one
//! match, also any Checkpoint the host signed twice. Exits 1 if anything
//! was found, 2 if a bundle cannot be read.

use std::process::ExitCode;

fn main() -> ExitCode {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: fpp-audit <bundle.fppb>...");
        return ExitCode::from(2);
    }
    let mut bundles = Vec::new();
    let mut found = false;
    for path in &paths {
        let bundle = match std::fs::read(path)
            .map_err(|e| e.to_string())
            .and_then(|b| fpp_audit::parse(&b).map_err(|e| e.to_string()))
        {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{path}: {e}");
                return ExitCode::from(2);
            }
        };
        let report = fpp_audit::audit(&bundle);
        let role = match bundle.meta.as_ref().map(|m| m.role) {
            Some(fpp_audit::ROLE_HOST) => "host",
            _ => "player",
        };
        println!(
            "{path}: {role}, {} commits, {} frames, {} units, {} checkpoints, {} outcomes: {}",
            report.commits,
            report.frames,
            report.units,
            report.checkpoints,
            report.outcomes,
            if report.clean() { "clean" } else { "FINDINGS" }
        );
        for finding in &report.findings {
            println!("  finding: {finding}");
        }
        for note in &report.notes {
            println!("  note: {note}");
        }
        found |= !report.clean();
        bundles.push(bundle);
    }
    for finding in fpp_audit::equivocations(&bundles) {
        println!("across bundles: {finding}");
        found = true;
    }
    if found {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
