pub fn truncate_to_char_boundary(text: &mut String, max_bytes: usize) {
    if text.len() <= max_bytes {
        return;
    }

    let mut end = max_bytes.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_ascii_by_bytes() {
        let mut text = "abcdef".to_string();

        truncate_to_char_boundary(&mut text, 3);

        assert_eq!(text, "abc");
    }

    #[test]
    fn truncates_multibyte_without_panic() {
        let mut text = "错误信息很长".to_string();

        truncate_to_char_boundary(&mut text, 5);

        assert_eq!(text, "错");
    }
}
