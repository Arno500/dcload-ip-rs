pub fn build_dc_toc(start_sector: u32, num_sectors: u32) -> Vec<u8> {
    let mut toc = [u32::MAX; 102];
    if start_sector > 150 {
        toc[0] = make_dc_toc_entry(150, 1, 0);
        toc[1] = make_dc_toc_entry(start_sector, 1, 4);
        toc[100] = make_dc_toc_track(2);
    } else {
        toc[0] = make_dc_toc_entry(start_sector, 1, 4);
        toc[100] = make_dc_toc_track(1);
    }
    toc[99] = make_dc_toc_track(1);
    toc[101] = make_dc_toc_entry(start_sector.saturating_add(num_sectors), 1, 4);

    let mut out = Vec::with_capacity(toc.len() * 4);
    for val in toc {
        out.extend_from_slice(&val.to_le_bytes());
    }
    out
}

fn make_dc_toc_entry(lba: u32, adr: u32, ctrl: u32) -> u32 {
    lba | (adr << 24) | (ctrl << 28)
}

fn make_dc_toc_track(n: u32) -> u32 {
    (n & 0xff) << 16
}
