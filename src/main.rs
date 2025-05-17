use std::fs;
use anyhow::Result;
use ppc750cl as disasm;
use byteorder::{self, BigEndian, ByteOrder};

fn address_to_offset(address: usize) -> usize {
    address - 0x1D1C85C
}

fn code_to_instruction(code: u32) -> String {
    let result =  disasm::Ins::new(code).simplified().to_string();

    if result != "<illegal>" {
        result
    } else {
        format!("<illegal; found: 0x{:08X}>", code)
    }
}

fn main() -> Result<()> {
    let elf = fs::read("scratch/pj023.elf")?;

    // let command = [
        //     "gdump",        // the executable
        
        //     "-N",           // only apply the flags we explicitly want
        
        //     "-ytext",       // text section only
    //     "-ylabfunc",    // function symbols only
    //     "-nx",          // do not demangle symbols
    
    //     "-raw",         // display as hex
    //     // "-cooked", // display as assembly
    // ];
    
    let function_start: usize = 0x02aaffcc;
    let _function_end: usize = function_start + 0x68;
    
    let asm = &elf[address_to_offset(function_start) .. address_to_offset(function_start) + 0x68];
    
    // let actual = 0x00D93770;

    // println!("{:X}", function_start - actual);

    let mut offs = 0;

    while offs < asm.len() {
        let code = BigEndian::read_u32(&asm[offs..offs + 4]);

        println!("{}", code_to_instruction(code));

        offs += 4;
    }

    // println!("{:X}", asm);
    // println!("Hello, world!");

    Ok(())
}
