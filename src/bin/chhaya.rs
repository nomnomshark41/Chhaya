#![forbid(unsafe_code)]

use std::fs;
use std::fs::File;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chhaya::directory::KeyDirectory;
use chhaya::pin::PinPolicy;
use chhaya::MlKem1024;
use clap::{Args, Parser, Subcommand};
use libipld::cid::Cid;

#[derive(Parser)]
#[command(name = "chhaya", about = "Chhaya utility CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(subcommand)]
    Pin(PinCommand),
    #[command(subcommand)]
    Car(CarCommand),
}

#[derive(Subcommand)]
enum PinCommand {
    Ls(PinArgs),
    Prune(PinPruneArgs),
}

#[derive(Subcommand)]
enum CarCommand {
    Export(CarExportArgs),
    Import(CarImportArgs),
}

#[derive(Args, Clone)]
struct PinArgs {
    #[arg(long, default_value = "pins.json")]
    store: PathBuf,
}

#[derive(Args, Clone)]
struct CarExportArgs {
    cid: String,
    #[arg(long, value_name = "FILE")]
    out: PathBuf,
    #[arg(long, value_name = "STORE", default_value = "directory.car")]
    store: PathBuf,
}

#[derive(Args, Clone)]
struct CarImportArgs {
    file: PathBuf,
    #[arg(long, value_name = "STORE", default_value = "directory.car")]
    store: PathBuf,
}

#[derive(Args)]
struct PinPruneArgs {
    #[command(flatten)]
    common: PinArgs,
    #[arg(long, value_name = "COUNT")]
    keep: usize,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Pin(cmd) => handle_pin(cmd),
        Command::Car(cmd) => handle_car(cmd),
    }
}

fn handle_pin(command: PinCommand) -> Result<()> {
    match command {
        PinCommand::Ls(args) => handle_pin_ls(args),
        PinCommand::Prune(args) => handle_pin_prune(args),
    }
}

fn handle_car(command: CarCommand) -> Result<()> {
    match command {
        CarCommand::Export(args) => handle_car_export(args),
        CarCommand::Import(args) => handle_car_import(args),
    }
}

fn handle_pin_ls(args: PinArgs) -> Result<()> {
    let policy = PinPolicy::load_from_path(&args.store)
        .with_context(|| format!("failed to load {}", args.store.display()))?;
    let pins = policy.pins();
    if pins.is_empty() {
        println!("no pins");
        return Ok(());
    }
    for record in pins {
        println!("{}", record.cid);
        for reason in &record.reasons {
            println!("  - {}", reason);
        }
    }
    Ok(())
}

fn handle_pin_prune(args: PinPruneArgs) -> Result<()> {
    let mut policy = PinPolicy::load_from_path(&args.common.store)
        .with_context(|| format!("failed to load {}", args.common.store.display()))?;
    let removed = policy.prune_checkpoints_to(args.keep);
    policy
        .save_to_path(&args.common.store)
        .with_context(|| format!("failed to save {}", args.common.store.display()))?;
    println!(
        "pruned {removed} checkpoints; retaining {} (keep = {})",
        policy.checkpoint_count(),
        policy.keep_checkpoints()
    );
    Ok(())
}

fn handle_car_export(args: CarExportArgs) -> Result<()> {
    let cid =
        Cid::try_from(args.cid.as_str()).with_context(|| format!("invalid CID {}", args.cid))?;
    let mut directory = KeyDirectory::<MlKem1024>::new();
    let store_file = File::open(&args.store)
        .with_context(|| format!("failed to open {}", args.store.display()))?;
    directory
        .import_car(store_file)
        .with_context(|| format!("failed to load store {}", args.store.display()))?;
    let mut out_file = File::create(&args.out)
        .with_context(|| format!("failed to create {}", args.out.display()))?;
    directory
        .export_car(&cid, &mut out_file)
        .with_context(|| format!("failed to export CAR to {}", args.out.display()))?;
    println!(
        "exported snapshot {cid} to {} ({} records)",
        args.out.display(),
        directory.record_count()
    );
    Ok(())
}

fn handle_car_import(args: CarImportArgs) -> Result<()> {
    let mut directory = KeyDirectory::<MlKem1024>::new();
    let input = File::open(&args.file)
        .with_context(|| format!("failed to open {}", args.file.display()))?;
    let root = directory
        .import_car(input)
        .with_context(|| format!("failed to import {}", args.file.display()))?;
    if args.store != args.file {
        if let Some(parent) = args.store.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
        }
        fs::copy(&args.file, &args.store)
            .with_context(|| format!("failed to update store {}", args.store.display()))?;
    }
    println!(
        "imported snapshot {root} with {} records",
        directory.record_count()
    );
    Ok(())
}
