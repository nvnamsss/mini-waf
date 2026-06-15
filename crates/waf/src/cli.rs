use clap::{Parser, Subcommand};

/// Mini WAF — lightweight security gateway.
#[derive(Parser)]
#[command(name = "waf", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the WAF proxy and dashboard API.
    Run(RunArgs),
}

#[derive(clap::Args)]
pub struct RunArgs {
    /// Path to waf.toml configuration file.
    #[arg(short, long, default_value = "config/waf.toml")]
    pub config: std::path::PathBuf,
}

pub fn run() {
    let cli = Cli::parse();

    match cli.command {
        Command::Run(args) => {
            let rt = tokio::runtime::Runtime::new().expect("failed to build tokio runtime");
            rt.block_on(run_async(args)).expect("waf exited with error");
        }
    }
}

async fn run_async(args: RunArgs) -> anyhow::Result<()> {
    // Initialise structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    tracing::info!("loading config from {:?}", args.config);
    let config = waf_engine::config::schema::Config::load_from_file(&args.config)?;

    tracing::info!("initialising application state");
    let state = waf_engine::state::store::AppState::init(config.clone())?;

    let proxy_addr = config.server.bind.clone();
    let api_addr = config.dashboard_api.bind.clone();

    tracing::info!("starting proxy on {}", proxy_addr);
    tracing::info!("starting dashboard API on {}", api_addr);

    // Run proxy and API concurrently; either task failing stops both.
    tokio::try_join!(
        waf_proxy::server::serve(&proxy_addr, state.clone()),
        waf_api::server::serve(&api_addr, state.clone()),
    )?;

    Ok(())
}
