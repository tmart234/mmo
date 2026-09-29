use gs_sim::ledger::Ledger;

#[test]
fn ledger_appends_json_lines() {
    let mut led = Ledger::open_for_session("test").expect("open ledger");
    led.append_line(r#"{"tick":1,"slot":0,"op":"Move","x":0.500,"y":0.000}"#);
    let body = std::fs::read_to_string("ledger/session_test.log").expect("read ledger");
    let last = body.lines().rev().find(|l| !l.is_empty()).expect("a line");
    assert!(last.contains(r#""op":"Move""#), "{last}");
}
