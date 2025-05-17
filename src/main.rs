use std::fs;
use std::process::Command;
use anyhow::{Result, bail};
// use ppc750cl as disasm;
use byteorder::{self, BigEndian, ByteOrder};
use clap::Parser;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Parser, Debug)]
#[command(name = "merino-tool")]
struct Args {
    /// Path to the .elf file
    elf_path: String,
    /// Path to your CSV of symbols
    symbols_path: String,
    /// Path to the object file
    object_path: String,
    /// Symbol to diff
    target_symbol: String,
}

/* Utility */

#[inline]
fn address_to_offset(address: usize) -> usize {
    address - 0x1D1C85C
}

fn addresses_to_offsets(addresses: (usize, usize)) -> (usize, usize) {
    (address_to_offset(addresses.0), address_to_offset(addresses.1))
}

// fn code_to_instruction(code: u32) -> String {
//     let result =  disasm::Ins::new(code).simplified().to_string();

//     if result != "<illegal>" {
//         result
//     } else {
//         format!("<illegal; found: 0x{:08X}>", code)
//     }
// }


/* */

#[derive(Debug, Deserialize, Clone)]
struct Symbol {
    mangled: String,
    start_address: usize,
    end_address: usize
}


fn main() -> Result<()> {
    let args = Args::parse();

    // load elf
    let elf = fs::read(&args.elf_path).expect("Couldn't load ELF");

    // load symbols/functions
    // let mut symbols: Vec<Symbol> = Vec::new();
    let mut reader = csv::Reader::from_reader(fs::File::open(&args.symbols_path).expect("Couldn't load CSV"));

    // mangled symbol, assembly
    let mut functions: HashMap<String, Vec<u32>> = HashMap::new();

    for result in reader.deserialize() {
        // symbol
        let symbol: Symbol = result?;
        
        // functions
        let offsets = addresses_to_offsets((symbol.start_address, symbol.end_address));
        
        let bytes = &elf[offsets.0..offsets.1];
        
        let mut asm = Vec::new();
        
        let mut offs = 0;
        while offs < bytes.len() {
            asm.push(BigEndian::read_u32(&bytes[offs..offs + 4]));    
            offs += 4;
        }
        
        functions.insert(symbol.mangled, asm);
    }

    // run command

    let out = Command::new("tools/gdump.exe")
        .arg("-N")              // only apply the flags we explicitly ask for
        .arg("-ytext")          // only display the .text section
        .arg("-ylabfunc")       // only display function symbols
        .arg("-nx")             // do not demangle symbols
        .arg(&args.object_path) // the object file to dump
    .output()?;

    let string_output = String::from_utf8_lossy(&out.stdout);
    
    // load built function asm

    let lines = string_output.lines();

    let mut symbol_found = false;

    let mut symbol_asm = Vec::new();

    for line in lines {
        // check if it's a symbol
        if line.ends_with(':') {
            if symbol_found {
                break; // we already processed our target symbol
            }

            // trim symbol name and colon
            let name = line.trim_end_matches(':').trim();
            symbol_found = name.ends_with(&args.target_symbol);
            continue;
        }

        if !symbol_found {
            continue;
        }

        // found the symbol. the assembly should be immediately after

        // read the first 8 characters after the colon
        let hex_asm = &line[11..19];
        
        let code = u32::from_str_radix(hex_asm, 16)?;
        symbol_asm.push(code);
    }

    // print if the code is different

    if !symbol_found {
        bail!("Failed to find symbol {} in {}", &args.target_symbol, &args.symbols_path);
    }


    println!("Identical: {}", functions[&args.target_symbol] == symbol_asm);

    println!("Original:");
    for instr in &functions[&args.target_symbol] {
        print!("{:08X} ", instr);
    }
    
    println!();
    
    println!("Compiled:");
    for instr in symbol_asm {
        print!("{:08X} ", instr);
    }

    Ok(())
}
