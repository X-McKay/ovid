//! Minimal, defensive DNS wire-format parsing for observed resolver
//! traffic (FR-033's DNS capture, process-backend edition).
//!
//! In MicroVM mode the gateway *serves* DNS and knows every name→address
//! binding authoritatively. The process backend has no gateway, so name
//! identity is recovered from the workload's own resolver traffic: strace
//! renders UDP payloads on port-53 sockets as escaped C strings, which are
//! decoded here and parsed as DNS packets. Everything is bounds-checked
//! and failure-tolerant — these bytes are attacker-influenced (§13.9's
//! decoder caution applies even to this tiny parser), so any malformed
//! input yields `None`, never a panic.

use std::net::IpAddr;

/// A parsed DNS query or response, reduced to what evidence needs.
#[derive(Debug, PartialEq, Eq)]
pub struct DnsPacket {
    pub is_response: bool,
    /// First question name (lowercased).
    pub question: String,
    /// A/AAAA answers, attributed to the question name (CNAME chains
    /// collapse onto the name the workload asked for).
    pub answers: Vec<IpAddr>,
}

/// Decode strace's escaped C-string rendering into raw bytes.
///
/// strace (without `-x`) renders unprintable bytes as octal `\NNN` (1–3
/// digits) plus the short escapes `\n \t \r \v \f \" \\`.
pub fn decode_strace_bytes(escaped: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(escaped.len());
    let mut chars = escaped.bytes().peekable();
    while let Some(byte) = chars.next() {
        if byte != b'\\' {
            out.push(byte);
            continue;
        }
        match chars.next() {
            Some(b'n') => out.push(b'\n'),
            Some(b't') => out.push(b'\t'),
            Some(b'r') => out.push(b'\r'),
            Some(b'v') => out.push(0x0b),
            Some(b'f') => out.push(0x0c),
            Some(b'"') => out.push(b'"'),
            Some(b'\\') => out.push(b'\\'),
            Some(digit @ b'0'..=b'7') => {
                let mut value = (digit - b'0') as u32;
                for _ in 0..2 {
                    match chars.peek() {
                        Some(&next @ b'0'..=b'7') => {
                            value = value * 8 + (next - b'0') as u32;
                            chars.next();
                        }
                        _ => break,
                    }
                }
                out.push((value & 0xff) as u8);
            }
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// Extract the contents of double-quoted strings from a strace line,
/// respecting backslash escapes (so `\"` inside a payload does not
/// terminate the string).
pub fn extract_quoted_strings(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let start = index + 1;
            let mut cursor = start;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'\\' => cursor += 2,
                    b'"' => break,
                    _ => cursor += 1,
                }
            }
            if cursor <= bytes.len() {
                let end = cursor.min(bytes.len());
                if let Ok(slice) = std::str::from_utf8(&bytes[start..end]) {
                    out.push(slice);
                }
            }
            index = cursor + 1;
        } else {
            index += 1;
        }
    }
    out
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

/// Read a (possibly compressed) DNS name starting at `offset`. Returns the
/// lowercased dotted name and the offset just past the name in the
/// *original* (non-pointer) position.
fn read_name(bytes: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumps = 0;
    let mut end_offset: Option<usize> = None;
    loop {
        let len = *bytes.get(offset)? as usize;
        if len == 0 {
            if end_offset.is_none() {
                end_offset = Some(offset + 1);
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            // Compression pointer.
            let pointer = ((len & 0x3f) << 8) | *bytes.get(offset + 1)? as usize;
            if end_offset.is_none() {
                end_offset = Some(offset + 2);
            }
            jumps += 1;
            if jumps > 10 || pointer >= bytes.len() {
                return None; // pointer loop or out of bounds
            }
            offset = pointer;
            continue;
        }
        if len > 63 || labels.len() > 32 {
            return None;
        }
        let label = bytes.get(offset + 1..offset + 1 + len)?;
        // Restrict to hostname-plausible bytes: this parser runs against
        // arbitrary UDP payloads on port 53, and rejecting implausible
        // labels avoids fabricating names from non-DNS traffic (§6.6).
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'*'))
        {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).to_lowercase());
        offset += 1 + len;
    }
    if labels.is_empty() {
        return None;
    }
    Some((labels.join("."), end_offset.unwrap_or(offset)))
}

/// Parse a DNS packet, returning the question name and any A/AAAA answers.
pub fn parse_dns_packet(bytes: &[u8]) -> Option<DnsPacket> {
    if bytes.len() < 12 {
        return None;
    }
    let flags = read_u16(bytes, 2)?;
    let is_response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0xf;
    if opcode != 0 {
        return None; // only standard queries carry dependency identity
    }
    let question_count = read_u16(bytes, 4)?;
    let answer_count = read_u16(bytes, 6)?;
    if question_count == 0 || question_count > 4 {
        return None;
    }

    let (question, mut offset) = read_name(bytes, 12)?;
    let qtype = read_u16(bytes, offset)?;
    let qclass = read_u16(bytes, offset + 2)?;
    // A, AAAA, CNAME, ANY, HTTPS/SVCB in class IN/ANY are plausible
    // hostname lookups; anything else (PTR, SRV, …) is not a service
    // dependency identity.
    if !matches!(qtype, 1 | 5 | 28 | 65 | 255) || !matches!(qclass, 1 | 255) {
        return None;
    }
    offset += 4;

    let mut answers = Vec::new();
    if is_response {
        // Parse answers defensively; a truncated capture (strace -s bound)
        // yields the answers that fit.
        for _ in 0..answer_count.min(32) {
            let Some((_, after_name)) = read_name(bytes, offset) else {
                break;
            };
            let Some(rtype) = read_u16(bytes, after_name) else {
                break;
            };
            let Some(rdlen) = read_u16(bytes, after_name + 8) else {
                break;
            };
            let rdata_start = after_name + 10;
            let Some(rdata) = bytes.get(rdata_start..rdata_start + rdlen as usize) else {
                break;
            };
            match (rtype, rdlen) {
                (1, 4) => {
                    answers.push(IpAddr::from([rdata[0], rdata[1], rdata[2], rdata[3]]));
                }
                (28, 16) => {
                    let mut sixteen = [0u8; 16];
                    sixteen.copy_from_slice(rdata);
                    answers.push(IpAddr::from(sixteen));
                }
                _ => {} // CNAME/other rdata: chain collapses onto question
            }
            offset = rdata_start + rdlen as usize;
        }
    }

    Some(DnsPacket {
        is_response,
        question,
        answers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a query packet for `name` (A, IN).
    fn query(name: &str) -> Vec<u8> {
        let mut packet = vec![0xb8, 0x84, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.extend_from_slice(&[0, 0, 1, 0, 1]); // root, A, IN
        packet
    }

    #[test]
    fn decodes_octal_escapes() {
        assert_eq!(
            decode_strace_bytes(r"\270\204\1\0\10temporal"),
            vec![0xb8, 0x84, 1, 0, 8, b't', b'e', b'm', b'p', b'o', b'r', b'a', b'l']
        );
        assert_eq!(decode_strace_bytes(r#"a\"b\\c\n"#), b"a\"b\\c\n".to_vec());
    }

    #[test]
    fn extracts_quoted_strings_with_escapes() {
        let line = r#"sendto(6, "\270\204\1\0", 34, 0, {sin_addr=inet_addr("8.8.8.8")}, 16) = 34"#;
        let strings = extract_quoted_strings(line);
        assert_eq!(strings, vec![r"\270\204\1\0", "8.8.8.8"]);
        let tricky = r#"x "pay\"load" y"#;
        assert_eq!(extract_quoted_strings(tricky), vec![r#"pay\"load"#]);
    }

    #[test]
    fn parses_query_packet() {
        let packet = parse_dns_packet(&query("temporal.download")).unwrap();
        assert!(!packet.is_response);
        assert_eq!(packet.question, "temporal.download");
        assert!(packet.answers.is_empty());
    }

    #[test]
    fn parses_response_with_compression_and_a_records() {
        // Response: question temporal.download, two A answers using a
        // compression pointer back to offset 12.
        let mut packet = query("temporal.download");
        packet[2] = 0x81; // QR=1
        packet[3] = 0x80;
        packet[7] = 2; // ANCOUNT=2
        for ip in [[104u8, 21, 27, 83], [172, 67, 141, 216]] {
            packet.extend_from_slice(&[0xc0, 0x0c]); // pointer to question name
            packet.extend_from_slice(&[0, 1, 0, 1]); // A, IN
            packet.extend_from_slice(&[0, 0, 0, 60]); // TTL
            packet.extend_from_slice(&[0, 4]); // RDLENGTH
            packet.extend_from_slice(&ip);
        }
        let parsed = parse_dns_packet(&packet).unwrap();
        assert!(parsed.is_response);
        assert_eq!(parsed.question, "temporal.download");
        assert_eq!(
            parsed.answers,
            vec![
                "104.21.27.83".parse::<IpAddr>().unwrap(),
                "172.67.141.216".parse().unwrap()
            ]
        );
    }

    #[test]
    fn truncated_response_yields_partial_answers() {
        let mut packet = query("example.com");
        packet[2] = 0x81;
        packet[7] = 2;
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 1]); // second answer cut off
        let parsed = parse_dns_packet(&packet).unwrap();
        assert_eq!(parsed.answers.len(), 1);
    }

    #[test]
    fn rejects_non_dns_garbage_and_loops() {
        assert_eq!(parse_dns_packet(b"GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse_dns_packet(&[0u8; 11]), None);
        // Self-referencing compression pointer must not loop forever.
        let mut evil = vec![0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        evil.extend_from_slice(&[0xc0, 0x0c]); // name points at itself
        evil.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(parse_dns_packet(&evil), None);
        // Binary garbage with implausible labels.
        let mut garbage = vec![0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        garbage.extend_from_slice(&[3, 0xff, 0xfe, 0xfd, 0]);
        garbage.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(parse_dns_packet(&garbage), None);
    }
}
