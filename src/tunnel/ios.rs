// TODO:
// sync -> string
// connect -> list of endpoints
// get logs -> string
// upload_packet
// download_packet -> bytes

#[no_mangle]
pub extern "C" fn call_geph(opt: *const c_char) -> *mut c_char {
    let inner = || {
        let c_str = unsafe { CStr::from_ptr(opt) };
        // if c_str.to_str()?.contains("connect") {
        //     anyhow::bail!("lol always fail connects")
        // }
        let args: Vec<&str> = serde_json::from_str(c_str.to_str()?)?;

        let mut buf = BufferRedirect::stdout()?;
        let mut output = String::new();
        std::env::set_var("GEPH_RECURSIVE", "1"); // no forking in iOS
        start_with_args(args)?;
        buf.read_to_string(&mut output)?;
        Ok::<_, anyhow::Error>(output)
    };

    let output = match inner() {
        Ok(output) => output,
        Err(err) => format!("ERROR!!!! {:?}", err),
    };

    CString::new(output).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn upload_packet(pkt: *const c_uchar, len: c_int) {
    unsafe {
        let slice = std::slice::from_raw_parts(pkt as *mut u8, len as usize);
        let bytes: Bytes = slice.into();
        UP_CHANNEL.0.send(bytes).unwrap();
    }
}

#[no_mangle]
pub extern "C" fn download_packet(buffer: *mut c_uchar, buflen: c_int) -> c_int {
    let pkt = DOWN_CHANNEL.1.recv().unwrap();
    let pkt_ref = pkt.as_ref();
    unsafe {
        let mut slice: &mut [u8] =
            std::slice::from_raw_parts_mut(buffer as *mut u8, buflen as usize);
        if pkt.len() < slice.len() {
            if slice.write_all(pkt_ref).is_err() {
                -1
            } else {
                pkt.len() as c_int
            }
        } else {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn check_bridges(buffer: *mut c_char, buflen: c_int) -> c_int {
    let mut ips: Vec<String> = Vec::new();

    if let Some(rem_addr) = tunman::getsess::REMOTE_ADDR.get() {
        let ip = match rem_addr {
            async_net::SocketAddr::V4(ip) => ip.to_string(),
            async_net::SocketAddr::V6(ip) => ip.to_string(),
        };
        ips.push(ip);
    }

    if let Some(bridges) = tunman::getsess::BRIDGES.get() {
        for bd in bridges {
            let ip = match bd.endpoint.ip() {
                async_net::IpAddr::V4(ip) => ip.to_string(),
                async_net::IpAddr::V6(ip) => ip.to_string(),
            };
            ips.push(ip);
        }
    }

    let ips = serde_json::json!(ips).to_string();
    eprintln!("ips is {}; with length {}", ips, ips.len());

    unsafe {
        let mut slice = std::slice::from_raw_parts_mut(buffer as *mut u8, buflen as usize);
        if ips.len() < slice.len() {
            if slice.write_all(ips.as_bytes()).is_err() {
                -1
            } else {
                ips.len() as c_int
            }
        } else {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn get_logs(buffer: *mut c_char, buflen: c_int) -> c_int {
    let output = LOG_LINES.recv().unwrap();
    unsafe {
        let mut slice: &mut [u8] =
            std::slice::from_raw_parts_mut(buffer as *mut u8, buflen as usize);
        if output.len() < slice.len() {
            if slice.write_all(output.as_bytes()).is_err() {
                -1
            } else {
                output.len() as c_int
            }
        } else {
            -1
        }
    }
}
