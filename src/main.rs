use rle_codec::{compress, decompress, reference};
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;

fn usage() -> &'static str {
    "TinyRLE demo (Rust API + x86_64 pure asm core)

Usage:
  rle-demo                 # built-in sample round-trip
  rle-demo compress  <in> <out>
  rle-demo decompress <in> <out>
  rle-demo bench
"
}

fn demo_sample() -> io::Result<()> {
    let input = b"AAAABBBAAAAAAAAAAAAAHello, TinyRLE!....~~~~;;;;";
    let backend = if cfg!(target_arch = "x86_64") {
        "x86_64 assembly"
    } else {
        "Rust reference"
    };

    let compressed = compress(input).expect("compress");
    let roundtrip = decompress(&compressed).expect("decompress");
    let ref_c = reference::compress(input).expect("ref");

    println!("backend     : {backend}");
    println!("input       : {} bytes  {:?}", input.len(), String::from_utf8_lossy(input));
    println!("compressed  : {} bytes  {:02x?}", compressed.len(), compressed);
    println!("ratio       : {:.2}%", 100.0 * compressed.len() as f64 / input.len() as f64);
    println!("matches ref : {}", compressed == ref_c);
    println!("round-trip  : {}", roundtrip == input.as_slice());
    Ok(())
}

fn read_all(path: &str) -> io::Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        fs::read(path)
    }
}

fn write_all(path: &str, data: &[u8]) -> io::Result<()> {
    if path == "-" {
        io::stdout().write_all(data)
    } else {
        fs::write(path, data)
    }
}

fn bench() {
    let mut payload = Vec::with_capacity(1 << 20);
    for i in 0..(1 << 20) {
        // Mix of runs and literals.
        payload.push(if i % 17 < 11 { b'X' } else { (i % 251) as u8 });
    }

    let t0 = std::time::Instant::now();
    let c = compress(&payload).expect("compress");
    let t1 = std::time::Instant::now();
    let d = decompress(&c).expect("decompress");
    let t2 = std::time::Instant::now();

    assert_eq!(d, payload);
    println!(
        "1 MiB mix -> {} bytes | compress {:?} | decompress {:?}",
        c.len(),
        t1 - t0,
        t2 - t1
    );
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        None => {
            if let Err(e) = demo_sample() {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        }
        Some("-h" | "--help" | "help") => {
            print!("{}", usage());
        }
        Some("compress") => {
            let Some(inp) = args.next() else {
                eprint!("{}", usage());
                return ExitCode::FAILURE;
            };
            let Some(out) = args.next() else {
                eprint!("{}", usage());
                return ExitCode::FAILURE;
            };
            match read_all(&inp).and_then(|data| {
                compress(&data)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
                    .and_then(|c| write_all(&out, &c))
            }) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("compress failed: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        Some("decompress") => {
            let Some(inp) = args.next() else {
                eprint!("{}", usage());
                return ExitCode::FAILURE;
            };
            let Some(out) = args.next() else {
                eprint!("{}", usage());
                return ExitCode::FAILURE;
            };
            match read_all(&inp).and_then(|data| {
                decompress(&data)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
                    .and_then(|d| write_all(&out, &d))
            }) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("decompress failed: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        Some("bench") => bench(),
        Some(other) => {
            eprintln!("unknown command: {other}\n{}", usage());
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
