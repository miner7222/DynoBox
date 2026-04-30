use anyhow::{Result, anyhow};

/// Validate `spl` is a strict calendar date in `YYYY-MM-DD` ASCII form.
pub(crate) fn validate_spl_format(flag_name: &str, spl: &str) -> Result<()> {
    let bytes = spl.as_bytes();
    let well_formed = bytes.len() == 10
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit);
    if !well_formed {
        return Err(anyhow!(
            "{flag_name} must be in YYYY-MM-DD format (got {:?})",
            spl
        ));
    }

    let year = parse_ascii_u32(&bytes[0..4]);
    let month = parse_ascii_u32(&bytes[5..7]);
    let day = parse_ascii_u32(&bytes[8..10]);
    if month == 0 || month > 12 {
        return Err(anyhow!("{flag_name} month out of range in {:?}", spl));
    }
    let max_day = days_in_month(year, month);
    if day == 0 || day > max_day {
        return Err(anyhow!("{flag_name} day out of range in {:?}", spl));
    }
    Ok(())
}

fn parse_ascii_u32(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |acc, byte| acc * 10 + u32::from(byte - b'0'))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}
