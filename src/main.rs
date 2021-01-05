use {
    anyhow::{
        Context,
        anyhow
    },
    std::io::Write,
    termcolor::WriteColor,
};

// total addr length = ipv6 = 39 (alphanum plus colons), port=6 (colon plus digits)
//const ROW_FORMATTING: &str = "{:5} {:45} {:45} {:9} {:5} {}";

fn main() -> anyhow::Result<()> {
    let cli_setup = clap::App::new("socklist")
        .about("List OS sockets with their data")
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .arg(clap::Arg::with_name("listening")
            .short("l")
            .help("Narrow down results to TCP sockets that are listening for incoming connections")
            .group("filter")
        )
        .arg(clap::Arg::with_name("established")
            .short("e")
            .help("Narrow down results to TCP sockets that have an established connection")
            .group("filter")
        )
        .arg(clap::Arg::with_name("ipv4")
            .short("4")
            .help("Narrow down results to IPv4 sockets")
            .group("filter")
        )
        .arg(clap::Arg::with_name("ipv6")
            .short("6")
            .help("Narrow down results to IPv6 sockets")
            .group("filter")
        )
        .arg(clap::Arg::with_name("udp")
            .short("u")
            .help("Narrow down results to UDP sockets")
            .group("filter")
        )
        .arg(clap::Arg::with_name("tcp")
            .short("t")
            .help("Narrow down results to TCP sockets")
            .group("filter")
        )
        ;
    let cli = cli_setup.get_matches();

    let sockets_info = {
        use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags};

        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
        get_sockets_info(af_flags, proto_flags)?
    };

    use sysinfo::{ProcessExt, SystemExt};
    let mut sysinfo = sysinfo::System::new_with_specifics(sysinfo::RefreshKind::new().with_processes());
    sysinfo.refresh_all();
    let procdata = sysinfo.get_processes();

    let mut stdout = {
        if atty::is(atty::Stream::Stdout) {
            termcolor::StandardStream::stdout(termcolor::ColorChoice::Auto)
        } else {
            termcolor::StandardStream::stdout(termcolor::ColorChoice::Never)
        }
    };
    let color_port = {
        let mut x = termcolor::ColorSpec::new();
        x.set_fg(Some(termcolor::Color::Red));
        x.set_intense(true);
        x
    };
    let color_cmdline = {
        let mut x = termcolor::ColorSpec::new();
        x.set_fg(Some(termcolor::Color::Cyan));
        x
    };
    let color_frame = {
        let mut x = termcolor::ColorSpec::new();
        x.set_fg(Some(termcolor::Color::Black));
        x.set_intense(true);
        x
    };

    println!("{:5} {:>45} {:>45} {:11} {:>5} {}", "PROTO", "LOCAL", "REMOTE", "STATE", "PID", "CMDLINE");
    stdout.set_color(&color_frame)?;
    println!("{:-<5} {:->45} {:->45} {:-<11} {:->5} {:-<7}", "", "", "", "", "", "");
    stdout.reset()?;

    for si in sockets_info {
        let si_pid: Option<sysinfo::Pid> = match si.associated_pids.iter().take(1).next() {
            Some(pid) if *pid != 0 => Some(*pid as sysinfo::Pid),
            _ => None,
        };

        let (proto, localaddr, localport, remote, state, istcp, isipv6) = match si.protocol_socket_info {
            netstat2::ProtocolSocketInfo::Tcp(tcp_si) => (
                format!("tcp{}", if tcp_si.local_addr.is_ipv6() { "6" } else { "4" }),
                format!("{}", tcp_si.local_addr),
                format!("{}", tcp_si.local_port),
                if tcp_si.state == netstat2::TcpState::Listen {
                    None
                } else {
                    Some(tcp_si.clone())
                },
                Some(tcp_si.state),
                true,
                tcp_si.local_addr.is_ipv6(),
            ),
            netstat2::ProtocolSocketInfo::Udp(udp_si) => (
                format!("udp{}", if udp_si.local_addr.is_ipv6() { "6" } else { "4" }),
                format!("{}", udp_si.local_addr),
                format!("{}", udp_si.local_port),
                None,
                None,
                false,
                udp_si.local_addr.is_ipv6(),
            ),
        };

        write!(&mut stdout, "{:5}", proto)?;

        write!(&mut stdout, " ")?;

        write!(&mut stdout, "{:>39}", localaddr)?;
        write!(&mut stdout, ":")?;
        stdout.set_color(&color_port)?;
        write!(&mut stdout, "{:5}", localport)?;
        stdout.reset()?;

        write!(&mut stdout, " ")?;

        match remote {
            Some(tcp_si) => {
                write!(&mut stdout, "{:>39}", tcp_si.remote_addr)?;
                write!(&mut stdout, ":")?;
                stdout.set_color(&color_port)?;
                write!(&mut stdout, "{:<5}", tcp_si.remote_port)?;
                stdout.reset()?;
            },
            None => write!(&mut stdout, "{:>45}", "-")?,
        };

        write!(&mut stdout, " ")?;

        write!(&mut stdout, "{:11}", match state {
            Some(it) => format!("{}", it),
            None => "-".to_string(),
        })?;

        write!(&mut stdout, " ")?;

        write!(&mut stdout, "{:>5}", {
            format!("{}", match si_pid {
                Some(pid) => format!("{}", pid),
                None => "-".to_string(),
            })
        })?;
        write!(&mut stdout, " ")?;
        stdout.set_color(&color_cmdline)?;
        write!(&mut stdout, "{}", {
            format!("{}", {
                match si_pid {
                    Some(si_pid) => match procdata.iter().find(|(pid, _)| **pid == si_pid) {
                        Some((_, data)) => {
                            let cmdline = data.cmd();
                            if !cmdline.is_empty() {
                                format!("{}", cmdline.join(" "))
                            } else {
                                let textpath = data.exe().to_string_lossy().to_string();
                                if !textpath.is_empty() {
                                    textpath
                                } else {
                                    "-".to_string()
                                }
                            }
                        },
                        None => "-".to_string(),
                    },
                    None => "-".to_string(),
                }
            })
        })?;
        stdout.reset()?;
        writeln!(&mut stdout)?;
    }
    

    Ok(())
}
