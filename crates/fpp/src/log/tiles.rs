//! C2SP `tlog-tiles`: the tree published as static files, so anyone can
//! fetch and check it from plain storage (a web server, a bucket, a CDN)
//! without asking the log for anything.
//!
//! - `tile/<L>/<N>`: 256 hashes at height 8·L (a level-L hash covers 256^L
//!   leaves); `tile/<L>/<N>.p/<W>` while only W of them exist.
//! - `tile/entries/<N>`: the entries of level-0 tile N, each prefixed with
//!   its 16-bit big-endian length.
//! - `N` is split into 3-digit groups, all but the last prefixed `x`:
//!   1234067 is `x001/x234/067`.

/// Hashes per tile, and the tree height a tile level spans.
pub const WIDTH: u64 = 256;
pub const HEIGHT: u32 = 8;

pub fn encode_index(n: u64) -> String {
    let digits = n.to_string();
    let pad = (3 - digits.len() % 3) % 3;
    let digits = format!("{}{digits}", "0".repeat(pad));
    let groups: Vec<&str> = digits
        .as_bytes()
        .chunks(3)
        .map(|c| std::str::from_utf8(c).expect("digits"))
        .collect();
    let last = groups.len() - 1;
    groups
        .iter()
        .enumerate()
        .map(|(i, g)| {
            if i == last {
                g.to_string()
            } else {
                format!("x{g}")
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn with_width(base: String, width: u64) -> String {
    if width == WIDTH {
        base
    } else {
        format!("{base}.p/{width}")
    }
}

/// Path of hash tile `index` at `level`, `width` hashes wide.
pub fn tile_path(level: u8, index: u64, width: u64) -> String {
    with_width(format!("tile/{level}/{}", encode_index(index)), width)
}

/// Path of entry bundle `index`, `width` entries wide.
pub fn entries_path(index: u64, width: u64) -> String {
    with_width(format!("tile/entries/{}", encode_index(index)), width)
}

/// The tiles a tree of `size` leaves consists of, at `level` with `hashes`
/// hashes at that level: (index, width) of each, the last maybe partial.
pub fn tiles_at(hashes: u64) -> impl Iterator<Item = (u64, u64)> {
    (0..hashes.div_ceil(WIDTH)).map(move |n| (n, (hashes - n * WIDTH).min(WIDTH)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_follow_the_spec() {
        assert_eq!(encode_index(0), "000");
        assert_eq!(encode_index(67), "067");
        assert_eq!(encode_index(1234067), "x001/x234/067");
        assert_eq!(encode_index(1000), "x001/000");
        assert_eq!(tile_path(0, 1234067, 256), "tile/0/x001/x234/067");
        assert_eq!(tile_path(1, 3, 12), "tile/1/003.p/12");
        assert_eq!(entries_path(0, 1), "tile/entries/000.p/1");
        assert_eq!(tiles_at(257).collect::<Vec<_>>(), vec![(0, 256), (1, 1)]);
        assert_eq!(tiles_at(0).count(), 0);
    }
}
