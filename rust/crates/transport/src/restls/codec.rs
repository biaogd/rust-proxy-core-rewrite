//! Restls TLS 1.3 records. Oracle: restls-client-go v0.1.9, conn.go.
use std::io;

use rand::RngExt;

pub(super) const DEFAULT_SCRIPT: &str = "250?100<1,350~100<1,600~100,300~200,300~100";

pub(super) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone, Debug)]
pub(super) struct Line {
    target: usize,
    range: usize,
    pub response: Option<u8>,
}

impl Line {
    pub fn target(&self) -> usize {
        self.target
            + if self.range == 0 {
                0
            } else {
                rand::rng().random_range(0..self.range)
            }
    }
}

pub(super) fn parse_script(script: &str) -> io::Result<Vec<Line>> {
    let script = if script.is_empty() {
        DEFAULT_SCRIPT
    } else {
        script
    };
    let mut result = Vec::new();
    for line in script.replace(' ', "").split(',').filter(|s| !s.is_empty()) {
        let mut text = line;
        let target = integer(&mut text)?;
        if target > 32767 {
            return Err(invalid("Restls script target exceeds 32767"));
        }
        let mut parsed = Line {
            target,
            range: 0,
            response: None,
        };
        if text.starts_with(['~', '?']) {
            let once = text.starts_with('?');
            text = &text[1..];
            parsed.range = integer(&mut text)?;
            if parsed.range > 32767 || target + parsed.range > 32768 {
                return Err(invalid("Restls script range exceeds oracle limit"));
            }
            if once {
                parsed.target = parsed.target();
                parsed.range = 0;
            }
        }
        if let Some(rest) = text.strip_prefix('<') {
            text = rest;
            let count = integer(&mut text)?;
            if count >= 255 {
                return Err(invalid("Restls script response count must be below 255"));
            }
            parsed.response = Some(u8::try_from(count).map_err(|_| invalid("response overflow"))?);
        }
        if !text.is_empty() {
            return Err(invalid("invalid Restls script suffix"));
        }
        result.push(parsed);
    }
    Ok(result)
}

fn integer(text: &mut &str) -> io::Result<usize> {
    let end = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let value = text[..end]
        .parse()
        .map_err(|_| invalid("invalid Restls script integer"))?;
    *text = &text[end..];
    Ok(value)
}

pub(super) struct Records {
    pub key: [u8; 32],
    pub random: [u8; 32],
    pub sent: u64,
    pub received: u64,
    pub finished: Vec<u8>,
    pub script: Vec<Line>,
}

impl Records {
    fn hash(&self, incoming: bool) -> blake3::Hasher {
        let mut hash = blake3::Hasher::new_keyed(&self.key);
        hash.update(&self.random);
        hash.update(if incoming {
            b"server-to-client"
        } else {
            b"client-to-server"
        });
        hash.update(&if incoming { self.received } else { self.sent }.to_be_bytes());
        hash
    }

    pub fn encode(&mut self, data: &[u8], response: bool) -> io::Result<(Vec<u8>, usize, bool)> {
        let line = usize::try_from(self.sent)
            .ok()
            .and_then(|n| self.script.get(n));
        let target = line.map_or(data.len(), Line::target);
        let command = line.and_then(|l| l.response);
        let padding = if target == 0 {
            rand::rng().random_range(19..119)
        } else {
            target.saturating_sub(data.len())
        };
        // Match Go's maxPlaintext, but reject configurations that would panic there.
        let size = (target.min(data.len()) + padding + 12).min(16384);
        let used = size
            .checked_sub(12 + padding)
            .ok_or_else(|| invalid("Restls script padding exceeds record limit"))?;
        let mut record = vec![23, 3, 3];
        record.extend_from_slice(
            &u16::try_from(size)
                .map_err(|_| invalid("record too large"))?
                .to_be_bytes(),
        );
        record.resize(17, 0);
        record.extend_from_slice(&data[..used]);
        let mut pad = vec![0; padding];
        rand::rng().fill(&mut pad[..]);
        record.extend_from_slice(&pad);
        let mut mask = self.hash(false);
        mask.update(&record[17..record.len().min(49)]);
        record[13..15].copy_from_slice(
            &u16::try_from(used)
                .map_err(|_| invalid("record too large"))?
                .to_be_bytes(),
        );
        record[15..17].copy_from_slice(&command.map_or([0, 0], |n| [1, n]));
        for (byte, mask) in record[13..17].iter_mut().zip(mask.finalize().as_bytes()) {
            *byte ^= mask;
        }
        let mut auth = self.hash(false);
        auth.update(&self.finished);
        auth.update(&record[..5]);
        auth.update(&record[13..]);
        record[5..13].copy_from_slice(&auth.finalize().as_bytes()[..8]);
        self.finished.clear();
        self.sent = self
            .sent
            .checked_add(1)
            .ok_or_else(|| invalid("Restls counter overflow"))?;
        Ok((record, used, command.is_some() && !response))
    }

    pub fn decode(&self, record: &[u8]) -> io::Result<(Vec<u8>, u8)> {
        if record.len() < 17 || record[..3] != [23, 3, 3] {
            return Err(invalid("invalid Restls record"));
        }
        let mut auth = self.hash(true);
        auth.update(&record[..5]);
        auth.update(&record[13..]);
        // BLAKE3 Hash equality is constant time; extend the truncated tag with
        // the known suffix so the comparison still checks only its first 8 bytes.
        let expected = auth.finalize();
        let mut actual = *expected.as_bytes();
        actual[..8].copy_from_slice(&record[5..13]);
        if expected != blake3::Hash::from(actual) {
            return Err(invalid("Restls record authentication failed"));
        }
        let mut mask = self.hash(true);
        mask.update(&record[17..record.len().min(49)]);
        let mut fields = [0; 4];
        for ((out, byte), mask) in fields
            .iter_mut()
            .zip(&record[13..17])
            .zip(mask.finalize().as_bytes())
        {
            *out = byte ^ mask;
        }
        let length = usize::from(u16::from_be_bytes([fields[0], fields[1]]));
        if length > record.len() - 17 || fields[2] > 1 {
            return Err(invalid("invalid Restls length/command"));
        }
        Ok((
            record[17..17 + length].to_vec(),
            if fields[2] == 1 { fields[3] } else { 0 },
        ))
    }
}

/// Hash every key share, including GREASE, without the TLS vector lengths.
pub(super) fn session_id(key: &[u8; 32], hello: &[u8]) -> io::Result<[u8; 32]> {
    let mut hash = blake3::Hasher::new_keyed(key);
    let mut data = hello
        .get(38..)
        .ok_or_else(|| invalid("short ClientHello"))?;
    let sid_len = usize::from(take(&mut data, 1)?[0]);
    take(&mut data, sid_len)?;
    vector(&mut data)?; // cipher suites
    let comp_len = usize::from(take(&mut data, 1)?[0]);
    take(&mut data, comp_len)?;
    let mut extensions = vector(&mut data)?;
    let mut found = false;
    while !extensions.is_empty() {
        let typ = take(&mut extensions, 2)?;
        let mut value = vector(&mut extensions)?;
        if typ == [0, 51] {
            let mut shares = vector(&mut value)?;
            while !shares.is_empty() {
                hash.update(take(&mut shares, 2)?);
                hash.update(vector(&mut shares)?);
                found = true;
            }
        } else if typ == [0, 41] {
            // Resumption is disabled in the TLS 1.3 slice.
            return Err(invalid("Restls PSK authentication is not enabled"));
        }
    }
    if !found {
        return Err(invalid("Restls requires key shares"));
    }
    let mut sid = [0; 32];
    rand::rng().fill(&mut sid);
    sid[..16].copy_from_slice(&hash.finalize().as_bytes()[..16]);
    Ok(sid)
}

fn take<'a>(data: &mut &'a [u8], length: usize) -> io::Result<&'a [u8]> {
    if data.len() < length {
        return Err(invalid("truncated TLS vector"));
    }
    let (head, rest) = data.split_at(length);
    *data = rest;
    Ok(head)
}

fn vector<'a>(data: &mut &'a [u8]) -> io::Result<&'a [u8]> {
    let length = take(data, 2)?;
    take(
        data,
        usize::from(u16::from_be_bytes([length[0], length[1]])),
    )
}
