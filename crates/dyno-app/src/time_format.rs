//! Shared Unix-timestamp formatting helpers.
//!
//! Both `pipeline::confirm_rollback_change` (renders `ctime`-style
//! UTC dates for the rollback confirmation prompt) and
//! `report::PipelineReport::now` (ISO-8601 timestamps for the
//! HTML report) used to hand-roll Howard Hinnant's civil-from-days
//! algorithm with subtle divergence between the two copies — the
//! `era` branch was written `if z >= 0 { z }` in one and
//! `if z >= 0 { z / 146097 }` in the other, equivalent today but a
//! drift waiting to happen. This module exposes one common
//! `civil_from_days` + a `weekday_index` helper plus the two
//! formatters so future fixes land once.

/// Decompose `days_since_epoch` (days since 1970-01-01 UTC) into
/// `(year, month, day)`. Uses the branch-free Howard Hinnant
/// algorithm from <https://howardhinnant.github.io/date_algorithms.html>.
/// No leap-day edge cases; handles negative inputs (pre-epoch) via
/// the standard `era` shift.
pub fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// `[Sun=0, Mon=1, … Sat=6]` weekday index for `days_since_epoch`.
/// 1970-01-01 was a Thursday (index 4), used as the anchor.
pub fn weekday_index(days_since_epoch: i64) -> usize {
    ((days_since_epoch + 4).rem_euclid(7)) as usize
}

/// Format a Unix timestamp as e.g. `Thu Feb 26 02:40:50 UTC 2026`.
/// Used by the rollback confirmation prompt; mirrors the
/// human-readable form of `ctime(3)` with a `UTC` suffix.
pub fn format_unix_timestamp_utc(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    let sod = ts % 86_400;
    let hour = sod / 3600;
    let minute = (sod % 3600) / 60;
    let second = sod % 60;
    let weekday = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][weekday_index(days)];
    let (year, m, d) = civil_from_days(days);
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(m - 1) as usize];
    format!("{weekday} {month} {d:2} {hour:02}:{minute:02}:{second:02} UTC {year}")
}

/// Format a Unix timestamp as ISO-8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`).
/// Used by the HTML pipeline report.
pub fn format_unix_to_iso8601_utc(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    let sod = ts % 86_400;
    let hour = sod / 3600;
    let minute = (sod % 3600) / 60;
    let second = sod % 60;
    let (year, m, d) = civil_from_days(days);
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctime_epoch() {
        assert_eq!(format_unix_timestamp_utc(0), "Thu Jan  1 00:00:00 UTC 1970");
    }

    #[test]
    fn iso_epoch() {
        assert_eq!(format_unix_to_iso8601_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn ctime_specific_date() {
        // 2026-02-27 02:40:50 UTC = 1772160050
        assert_eq!(
            format_unix_timestamp_utc(1_772_160_050),
            "Fri Feb 27 02:40:50 UTC 2026"
        );
    }

    #[test]
    fn ctime_matches_iso_for_same_input() {
        let ts = 1_700_000_000;
        let ctime = format_unix_timestamp_utc(ts);
        let iso = format_unix_to_iso8601_utc(ts);
        // Both should reference 2023-11-14 22:13:20 UTC.
        assert!(ctime.contains("Nov 14"));
        assert!(iso.starts_with("2023-11-14T"));
    }
}
