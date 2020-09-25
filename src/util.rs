//! Functionality used by the whole project.
use std::ffi::CStr;

/// Return the uppercase hexadecimal character associated with `num < 16`.
#[doc(hidden)]
fn hex_char(num: u8) -> char {
    assert!(num < 16);
    if num < 10 {
        (b'0' + num) as char
    } else {
        (b'A' + num - 10) as char
    }
}

/// Returns a `String` that describes a `CString`.
///
/// If `cstr` is a valid ASCII string and contains no whitespace or non-printable
/// characters, then the string is returned unchanged but as a `String`.
///
/// Otherwise, the returned string is a representation of the `CString` that is
/// enclosed in double quotes and uses C-style escape sequences to represent
/// whitespace and bytes that are not printable ASCII.
///
/// # Examples
///
/// ```
/// let cstr = CStr::from_bytes_with_nul(b"helloworld\0").unwrap();
/// assert_eq!("helloworld", escaped_string(cstr));
///
/// let cstr = CStr::from_bytes_with_nul(b"hello world\0").unwrap();
/// assert_eq!("\"hello world\"", escaped_string(cstr));
///
/// let cstr = CStr::from_bytes_with_nul(b"\x7Fhello\rworld\n\0").unwrap();
/// assert_eq!("\"\\x7Fhello\\rworld\\n\"", escaped_string(cstr));
/// ```
pub fn escaped_string(cstr: &CStr) -> String {
    // This counts the number of printable and non-whitespace ASCII bytes.
    // Printable ASCII starts at the space and continues up to before DEL (127).
    let num_weird = cstr
        .to_bytes()
        .iter()
        .filter(|&&c| c <= b' ' || c >= 127)
        .count();
    if num_weird == 0 {
        // The above filter should reject any invalid ASCII characters, so this
        // unwrap should be guaranteed to not cause a panic.
        return cstr.to_str().unwrap().to_string();
    }

    // We'll do a rough estimate of the size of the new string here that
    // assumes each escape only needs two chars to represent it.
    let mut str2 = String::with_capacity(cstr.to_bytes().len() + num_weird + 2);
    str2.push('"');
    for &c in cstr.to_bytes().iter() {
        match c {
            b'\n' => { str2 += "\\n"; continue },
            b'\r' => { str2 += "\\r"; continue },
            b'\t' => { str2 += "\\t"; continue },
            b'\\' => { str2 += "\\\\"; continue },
            b'\0' => { str2 += "\\0"; continue },
            b'"' => { str2 += "\\\""; continue },
            _ => {},
        }

        // we'll accept spaces here, since we're now enclosed with quotes
        if b' ' <= c && c < 127 {
            str2.push(c as char);
            continue;
        }

        // SUPER weird char - just print it as a hex byte escape
        str2 += "\\x";
        str2.push(hex_char(c >> 4));
        str2.push(hex_char(c & 0xF));
    }
    str2.push('"');

    str2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escaped_string() {
        let cstr = CStr::from_bytes_with_nul(b"helloworld\0").unwrap();
        assert_eq!("helloworld", escaped_string(cstr));

        let cstr = CStr::from_bytes_with_nul(b"hello world\0").unwrap();
        assert_eq!("\"hello world\"", escaped_string(cstr));

        let cstr = CStr::from_bytes_with_nul(b"\x7Fhello\rworld\n\0").unwrap();
        assert_eq!("\"\\x7Fhello\\rworld\\n\"", escaped_string(cstr));
    }
}
