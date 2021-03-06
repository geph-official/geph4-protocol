use std::{
    io::{stdin, stdout},
    process::Stdio,
    time::Instant,
};

use bytes::Bytes;
use geph4_protocol::VpnStdio;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 {
        eprintln!("we are the parent");
        let cmd = std::process::Command::new(&args[0])
            .arg("lala")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut child_stdout = cmd.stdout.unwrap();
        let mut child_stdin = cmd.stdin.unwrap();
        let start_time = Instant::now();
        for count in 1.. {
            let pkt = VpnStdio {
                verb: 0,
                body: Bytes::copy_from_slice(&[0u8; 1500]),
            };
            pkt.write_blocking(&mut child_stdin).unwrap();
            VpnStdio::read_blocking(&mut child_stdout).unwrap();
            if count % 1000 == 0 {
                let speed = count as f64 / start_time.elapsed().as_secs_f64();
                eprintln!("{} RTs done; {} RT/s", count, speed);
            }
        }
    } else {
        eprintln!("we are the child");
        let mut stdin = stdin();
        let mut stdout = stdout();
        loop {
            let pkt = VpnStdio::read_blocking(&mut stdin).unwrap();
            pkt.write_blocking(&mut stdout).unwrap();
        }
    }
}
