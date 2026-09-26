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

/// `requested` (already validated as strict `YYYY-MM-DD`) is a later date
/// than `current`, the value read back from an image.
///
/// Both sides are compared as `(year, month, day)` so an OEM value that is
/// not zero-padded (`2024-1-5`) or carries stray whitespace still orders
/// correctly. A `current` that is not a date at all falls back to a plain
/// string comparison, which is what every caller did before.
pub(crate) fn is_newer_spl(requested: &str, current: &str) -> bool {
    match (parse_spl_date(requested), parse_spl_date(current)) {
        (Some(requested), Some(current)) => requested > current,
        _ => requested > current,
    }
}

/// Lenient `Y-M-D` parse for ordering: 1-4 digit year, 1-2 digit month/day.
fn parse_spl_date(value: &str) -> Option<(u32, u32, u32)> {
    let mut parts = value.trim().split('-');
    let mut field = |max_len: usize| -> Option<u32> {
        let part = parts.next()?;
        if part.is_empty() || part.len() > max_len || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let date = (field(4)?, field(2)?, field(2)?);
    parts.next().is_none().then_some(date)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_newer_spl_orders_by_calendar_date() {
        assert!(is_newer_spl("2026-05-01", "2025-12-05"));
        assert!(!is_newer_spl("2025-12-05", "2025-12-05"));
        assert!(!is_newer_spl("2025-01-01", "2025-12-05"));
        // Non-padded / padded-with-whitespace OEM values still compare by date;
        // a plain string comparison would get both of these wrong.
        assert!(is_newer_spl("2024-02-01", "2024-1-15"));
        assert!(!is_newer_spl(
            "2024-02-01",
            " 2024-10-1
"
        ));
    }

    #[test]
    fn is_newer_spl_falls_back_to_string_order_for_non_dates() {
        assert!(is_newer_spl("2024-02-01", ""));
        assert!(!is_newer_spl("2024-02-01", "unknown"));
    }
}
