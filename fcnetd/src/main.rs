use clap::Parser;
use tracing::level_filters::LevelFilter;

mod server;
use server::start;

#[derive(clap::Parser)]
#[command(name = "fcnetd", version = "0.1.0", about = "A daemon serving fcnet over a Unix socket")]
struct Cli {
    #[arg(help = "The user ID to assign to the socket for non-root access", long = "uid", short = 'U')]
    pub uid: Option<u32>,
    #[arg(
        help = "The group ID to assign to the socket for non-root access",
        long = "gid",
        short = 'G'
    )]
    pub gid: Option<u32>,
    #[arg(
        help = "The amount of threads to give to a multi_thread Tokio runtime, or to use a current_thread runtime instead of unspecified",
        long = "threads",
        short = 't'
    )]
    pub threads: Option<usize>,
    #[arg(
        help = "An optional single-line password that will be required to be written for every new connection if enabled",
        long = "password",
        short = 'p'
    )]
    pub password: Option<String>,
    #[arg(help = "The logging level to use", long = "log-level", short = 'L', default_value_t = CliLogLevel::Debug)]
    pub log_level: CliLogLevel,
    pub socket_path: String,
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum CliLogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl ToString for CliLogLevel {
    fn to_string(&self) -> String {
        match self {
            CliLogLevel::Trace => "trace",
            CliLogLevel::Debug => "debug",
            CliLogLevel::Info => "info",
            CliLogLevel::Warn => "warn",
            CliLogLevel::Error => "error",
        }
        .to_string()
    }
}

impl From<CliLogLevel> for LevelFilter {
    fn from(value: CliLogLevel) -> Self {
        match value {
            CliLogLevel::Trace => Self::TRACE,
            CliLogLevel::Debug => Self::DEBUG,
            CliLogLevel::Info => Self::INFO,
            CliLogLevel::Warn => Self::WARN,
            CliLogLevel::Error => Self::ERROR,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    tracing_subscriber::fmt().with_max_level(cli.log_level).init();

    if let Some(threads) = cli.threads {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(threads)
            .build()
            .expect("Could not build a Tokio multi_thread runtime")
            .block_on(start(cli));
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Could not build a Tokio current_thread runtime")
            .block_on(start(cli));
    }
}
