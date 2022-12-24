use windows::Win32::Foundation::CHAR;

/// Converts a list of char to a Rust String.
///
/// # Example
///
/// ```rust
/// use windows::Win32::Foundation::CHAR;
/// use batota::string::chars_to_string;
/// let chars = [CHAR(104), CHAR(101), CHAR(108), CHAR(108), CHAR(111), CHAR(0)];
/// assert_eq!(chars_to_string(&chars), "hello".to_owned());
/// ```
#[tracing::instrument(name = "string::chars_to_string", skip_all, fields(
    chars = ?chars
))]
pub fn chars_to_string(chars: &[CHAR]) -> String {
    let name_ends_at_index = {
        let mut i = 0;

        while i < chars.len() && chars[i].0 != 0 {
            i += 1;
        }

        i
    };

    let s: Vec<u8> = chars[0..name_ends_at_index]
        .into_iter()
        .map(|char| char.0)
        .collect();

    let s = String::from_utf8_lossy(s.as_ref()).to_string();

    tracing::Span::current().record("string", &s);

    s
}
