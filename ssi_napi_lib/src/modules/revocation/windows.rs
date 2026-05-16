use crate::modules::revocation::types::RevocationControlValues;
use chrono::{Datelike, NaiveDate, TimeZone, Timelike, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationWindowLayout {
    pub base_window_count: u32,
    pub confirmation_window_count: u32,
    pub total_window_count: u32,
    pub last_valid_window_index: u32,
    pub last_confirmation_window_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowUnit {
    Seconds,
    Minutes,
    Hours,
    Days,
    Weeks,
    Months,
    Years,
    Decades,
}

fn parse_window_unit(unit: &str) -> Result<WindowUnit, String> {
    match unit.trim().to_ascii_lowercase().as_str() {
        "second" | "seconds" => Ok(WindowUnit::Seconds),
        "minute" | "minutes" => Ok(WindowUnit::Minutes),
        "hour" | "hours" => Ok(WindowUnit::Hours),
        "day" | "days" => Ok(WindowUnit::Days),
        "week" | "weeks" => Ok(WindowUnit::Weeks),
        "month" | "months" => Ok(WindowUnit::Months),
        "year" | "years" => Ok(WindowUnit::Years),
        "decade" | "decades" => Ok(WindowUnit::Decades),
        other => Err(format!("unit_of_time não suportado: {}", other)),
    }
}

pub fn unit_to_seconds(unit: &str) -> Result<i64, String> {
    match parse_window_unit(unit)? {
        WindowUnit::Seconds => Ok(1),
        WindowUnit::Minutes => Ok(60),
        WindowUnit::Hours => Ok(3600),
        WindowUnit::Days => Ok(86_400),
        WindowUnit::Weeks => Ok(604_800),
        WindowUnit::Months | WindowUnit::Years | WindowUnit::Decades => Err(format!(
            "unit_of_time '{}' possui duração variável; use cálculo calendárico UTC",
            unit
        )),
    }
}

fn to_utc_datetime(ts: i64) -> Result<chrono::DateTime<Utc>, String> {
    Utc.timestamp_opt(ts, 0)
        .single()
        .ok_or_else(|| format!("Timestamp UTC inválido: {}", ts))
}

fn last_day_of_month(year: i32, month: u32) -> Result<u32, String> {
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };

    let first_of_next = NaiveDate::from_ymd_opt(next_year, next_month, 1).ok_or_else(|| {
        format!(
            "Data inválida ao calcular último dia do mês: {}/{}",
            year, month
        )
    })?;
    Ok(first_of_next
        .pred_opt()
        .ok_or_else(|| "Falha ao obter último dia do mês".to_string())?
        .day())
}

fn add_months_utc(ts: i64, months_to_add: i64) -> Result<i64, String> {
    let dt = to_utc_datetime(ts)?;
    let year = dt.year();
    let month0 = dt.month0() as i64;
    let total_month0 = (year as i64)
        .checked_mul(12)
        .and_then(|value| value.checked_add(month0))
        .and_then(|value| value.checked_add(months_to_add))
        .ok_or_else(|| "Overflow ao calcular deslocamento de meses".to_string())?;

    let new_year_i64 = total_month0.div_euclid(12);
    let new_month0 = total_month0.rem_euclid(12);
    let new_year =
        i32::try_from(new_year_i64).map_err(|_| "Ano fora da faixa suportada".to_string())?;
    let new_month =
        u32::try_from(new_month0 + 1).map_err(|_| "Mês fora da faixa suportada".to_string())?;

    let clamped_day = dt.day().min(last_day_of_month(new_year, new_month)?);
    let naive = NaiveDate::from_ymd_opt(new_year, new_month, clamped_day)
        .and_then(|date| date.and_hms_opt(dt.hour(), dt.minute(), dt.second()))
        .ok_or_else(|| "Falha ao compor data UTC com deslocamento mensal".to_string())?;

    Ok(Utc.from_utc_datetime(&naive).timestamp())
}

fn add_window_steps(
    start_time: i64,
    unit_of_time: &str,
    time_window: u32,
    steps: u32,
) -> Result<i64, String> {
    if time_window == 0 {
        return Err("time_window deve ser maior que zero".to_string());
    }

    let unit = parse_window_unit(unit_of_time)?;
    let steps_i64 = i64::from(steps);
    let time_window_i64 = i64::from(time_window);
    let total_units = steps_i64
        .checked_mul(time_window_i64)
        .ok_or_else(|| "Overflow no cálculo de múltiplas janelas".to_string())?;

    match unit {
        WindowUnit::Seconds
        | WindowUnit::Minutes
        | WindowUnit::Hours
        | WindowUnit::Days
        | WindowUnit::Weeks => {
            let unit_seconds: i64 = match unit {
                WindowUnit::Seconds => 1,
                WindowUnit::Minutes => 60,
                WindowUnit::Hours => 3600,
                WindowUnit::Days => 86_400,
                WindowUnit::Weeks => 604_800,
                _ => unreachable!(),
            };
            let delta = unit_seconds
                .checked_mul(total_units)
                .ok_or_else(|| "Overflow no cálculo da janela".to_string())?;
            start_time
                .checked_add(delta)
                .ok_or_else(|| "Overflow no início da janela".to_string())
        }
        WindowUnit::Months => add_months_utc(start_time, total_units),
        WindowUnit::Years => add_months_utc(
            start_time,
            total_units
                .checked_mul(12)
                .ok_or_else(|| "Overflow no cálculo de anos".to_string())?,
        ),
        WindowUnit::Decades => add_months_utc(
            start_time,
            total_units
                .checked_mul(120)
                .ok_or_else(|| "Overflow no cálculo de décadas".to_string())?,
        ),
    }
}

pub fn compute_window_count(
    start_time: i64,
    validity_end: i64,
    unit_of_time: &str,
    time_window: u32,
    extra_windows_for_fp: u32,
) -> Result<u32, String> {
    if validity_end < start_time {
        return Err("validity_end menor que start_time".to_string());
    }
    if time_window == 0 {
        return Err("time_window deve ser maior que zero".to_string());
    }

    let mut base_windows: u32 = 0;
    loop {
        let window_start = add_window_steps(start_time, unit_of_time, time_window, base_windows)?;
        if window_start > validity_end {
            break;
        }
        base_windows = base_windows
            .checked_add(1)
            .ok_or_else(|| "Overflow no total de janelas".to_string())?;
    }

    base_windows
        .checked_add(extra_windows_for_fp)
        .ok_or_else(|| "Overflow no total de janelas".to_string())
}

pub fn compute_base_window_count(
    start_time: i64,
    validity_end: i64,
    unit_of_time: &str,
    time_window: u32,
) -> Result<u32, String> {
    compute_window_count(start_time, validity_end, unit_of_time, time_window, 0)
}

pub fn compute_window_layout(
    start_time: i64,
    validity_end: i64,
    unit_of_time: &str,
    time_window: u32,
    extra_windows_for_fp: u32,
) -> Result<RevocationWindowLayout, String> {
    let base_window_count =
        compute_base_window_count(start_time, validity_end, unit_of_time, time_window)?;
    if base_window_count == 0 {
        return Err("base_window_count não pode ser zero".to_string());
    }

    let total_window_count = base_window_count
        .checked_add(extra_windows_for_fp)
        .ok_or_else(|| "Overflow no total de janelas".to_string())?;
    if total_window_count == 0 {
        return Err("total_window_count não pode ser zero".to_string());
    }

    Ok(RevocationWindowLayout {
        base_window_count,
        confirmation_window_count: extra_windows_for_fp,
        total_window_count,
        last_valid_window_index: base_window_count - 1,
        last_confirmation_window_index: total_window_count - 1,
    })
}

pub fn is_validity_window_index(layout: &RevocationWindowLayout, window_index: u32) -> bool {
    window_index <= layout.last_valid_window_index
}

pub fn is_confirmation_only_window_index(
    layout: &RevocationWindowLayout,
    window_index: u32,
) -> bool {
    window_index > layout.last_valid_window_index
        && window_index <= layout.last_confirmation_window_index
}

pub fn window_layout_from_control(
    control: &RevocationControlValues,
) -> Result<RevocationWindowLayout, String> {
    if control.window_count == 0 {
        return Err("window_count inválido no control".to_string());
    }

    let fallback_base_window_count = control
        .window_count
        .saturating_sub(control.extra_windows_for_fp)
        .max(1);
    let base_window_count = if control.base_window_count > 0 {
        control.base_window_count
    } else {
        fallback_base_window_count
    };
    let confirmation_window_count =
        if control.base_window_count > 0 || control.confirmation_window_count > 0 {
            control.confirmation_window_count
        } else {
            control.extra_windows_for_fp
        };

    let total_window_count = control.window_count.max(base_window_count);
    let last_valid_window_index = if control.last_valid_window_index > 0 || base_window_count == 1 {
        control.last_valid_window_index
    } else {
        base_window_count - 1
    };
    let last_confirmation_window_index =
        if control.last_confirmation_window_index > 0 || total_window_count == 1 {
            control.last_confirmation_window_index
        } else {
            total_window_count - 1
        };

    Ok(RevocationWindowLayout {
        base_window_count,
        confirmation_window_count,
        total_window_count,
        last_valid_window_index,
        last_confirmation_window_index,
    })
}

pub fn window_start_for_index(
    start_time: i64,
    unit_of_time: &str,
    time_window: u32,
    index: u32,
) -> Result<i64, String> {
    add_window_steps(start_time, unit_of_time, time_window, index)
}

pub fn window_index_for_timestamp(
    start_time: i64,
    unit_of_time: &str,
    time_window: u32,
    ts: i64,
) -> Result<u32, String> {
    if ts < start_time {
        return Err("Timestamp anterior ao start_time".to_string());
    }

    let mut index: u32 = 0;
    loop {
        let current_start = window_start_for_index(start_time, unit_of_time, time_window, index)?;
        let next_index = index
            .checked_add(1)
            .ok_or_else(|| "window_index fora da faixa".to_string())?;
        let next_start = window_start_for_index(start_time, unit_of_time, time_window, next_index)?;
        if ts < next_start {
            return Ok(index);
        }
        if current_start == next_start {
            return Err("Cálculo de janelas degenerado: início de janela não avançou".to_string());
        }
        index = next_index;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        compute_window_count, compute_window_layout, is_confirmation_only_window_index,
        is_validity_window_index, window_index_for_timestamp, window_start_for_index,
    };

    #[test]
    fn month_windows_clamp_day_in_utc() {
        let start_time = 1706664000i64; // 2024-01-31T01:20:00Z
        let second_window = window_start_for_index(start_time, "months", 1, 1).unwrap();
        let third_window = window_start_for_index(start_time, "months", 1, 2).unwrap();

        assert_eq!(second_window, 1709169600); // 2024-02-29T01:20:00Z
        assert_eq!(third_window, 1711848000); // 2024-03-31T01:20:00Z
    }

    #[test]
    fn year_and_decade_windows_preserve_calendar_rules() {
        let start_time = 1709208000i64; // 2024-02-29T12:00:00Z
        let next_year = window_start_for_index(start_time, "years", 1, 1).unwrap();
        let next_decade = window_start_for_index(start_time, "decades", 1, 1).unwrap();

        assert_eq!(next_year, 1740744000); // 2025-02-28T12:00:00Z
        assert_eq!(next_decade, 2024740800); // 2034-02-28T12:00:00Z
    }

    #[test]
    fn compute_window_count_supports_variable_units() {
        let start_time = 1706664000i64; // 2024-01-31T01:20:00Z
        let validity_end = 1711848000i64; // 2024-03-31T01:20:00Z
        let count = compute_window_count(start_time, validity_end, "months", 1, 1).unwrap();
        assert_eq!(count, 4);
    }

    #[test]
    fn compute_window_layout_separates_validity_and_confirmation_windows() {
        let start_time = 1706664000i64; // 2024-01-31T01:20:00Z
        let validity_end = 1711848000i64; // 2024-03-31T01:20:00Z
        let layout = compute_window_layout(start_time, validity_end, "months", 1, 2).unwrap();

        assert_eq!(layout.base_window_count, 3);
        assert_eq!(layout.confirmation_window_count, 2);
        assert_eq!(layout.total_window_count, 5);
        assert_eq!(layout.last_valid_window_index, 2);
        assert_eq!(layout.last_confirmation_window_index, 4);
        assert!(is_validity_window_index(&layout, 2));
        assert!(is_confirmation_only_window_index(&layout, 4));
        assert!(!is_confirmation_only_window_index(&layout, 2));
    }

    #[test]
    fn compute_window_layout_supports_ten_confirmation_windows() {
        let start_time = 1706664000i64; // 2024-01-31T01:20:00Z
        let validity_end = 1711848000i64; // 2024-03-31T01:20:00Z
        let layout = compute_window_layout(start_time, validity_end, "months", 1, 10).unwrap();

        assert_eq!(layout.base_window_count, 3);
        assert_eq!(layout.confirmation_window_count, 10);
        assert_eq!(layout.total_window_count, 13);
        assert_eq!(layout.last_valid_window_index, 2);
        assert_eq!(layout.last_confirmation_window_index, 12);
        assert!(is_confirmation_only_window_index(&layout, 12));
        assert!(!is_confirmation_only_window_index(&layout, 2));
    }

    #[test]
    fn window_index_for_timestamp_supports_months() {
        let start_time = 1706664000i64; // 2024-01-31T01:20:00Z
        let ts = 1710465600i64; // 2024-03-15T01:20:00Z
        let index = window_index_for_timestamp(start_time, "months", 1, ts).unwrap();
        assert_eq!(index, 1);
    }
}
