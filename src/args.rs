use crate::utils::GResult;

#[derive(Debug, Clone, Default)]
pub struct Args {
    pub is_server: bool,

    pub port: u16,
}

impl Args {
    pub fn usage() {
        println!("Usage:  ooclutter <client OR server>  -p PORT");
    }

    pub fn from_env() -> GResult<Self> {
        let mut s = Self::default();

        let mut argv = std::env::args().collect::<std::collections::VecDeque<_>>();
        let mut argc = argv.len() as isize;

        argv.pop_front();
        argc -= 1;

        if argc < 1 {
            return Err("Not enough arguments".into());
        }

        if !(argv[0] == "client" || argv[0] == "server") {
            return Err("Subcommand isn't `client` or `server`".into());
        }

        s.is_server = argv[0] == "server";

        argv.pop_front();
        argc -= 1;

        let mut i = -1;
        while i < argc - 1 {
            i += 1;

            let arg = &argv[i as usize];

            if arg == "-h" || arg == "--help" {
                Self::usage();
                return Err("Called usage.".into());
            }

            if arg == "-p" || arg == "--port" {
                if i + 1 >= argc {
                    return Err("Port flag present but no value provided.".into());
                }

                let port = &argv[i as usize + 1].parse::<u16>().unwrap();
                s.port = *port;

                i += 1;

                continue;
            }

            return Err(format!("Unknown argument: `{arg}`.").into());
        }

        Ok(s)
    }
}
