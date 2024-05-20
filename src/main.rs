extern crate clap;
extern crate colored;

use crate::colored::Colorize;
use exe::pe::VecPE;
use exe::types::{ImportDirectory, ImportData, CCharString};
use clap::Parser;




#[derive(Debug, Parser, Clone)]
#[command(name = "PE_Scrapper", version = "1.0", about = "Read PE file and extract imports modules.")]
struct Arguments {
    #[clap(short, long, name = "PE file to read")]
    file: String,
}


fn main() {

    let banner = "
                                                               
    ██████╗ ██╗   ██╗███████╗████████╗██╗   ██╗         
    ██╔══██╗██║   ██║██╔════╝╚══██╔══╝╚██╗ ██╔╝         
    ██████╔╝██║   ██║███████╗   ██║    ╚████╔╝          
    ██╔══██╗██║   ██║╚════██║   ██║     ╚██╔╝           
    ██║  ██║╚██████╔╝███████║   ██║      ██║            
    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝            
                                                        
    ██████╗ ██╗   ██╗███╗   ███╗██████╗ ███████╗██████╗ 
    ██╔══██╗██║   ██║████╗ ████║██╔══██╗██╔════╝██╔══██╗
    ██║  ██║██║   ██║██╔████╔██║██████╔╝█████╗  ██████╔╝
    ██║  ██║██║   ██║██║╚██╔╝██║██╔═══╝ ██╔══╝  ██╔══██╗
    ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║     ███████╗██║  ██║
    ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
    Author: HackTheSys   _*_*_*_   Version: 1.0                                                   \n\n";


let args = Arguments::parse();

let image = VecPE::from_disk_file(&args.file).unwrap();
let import_directory = ImportDirectory::parse(&image).unwrap();
print!("{}", banner.cyan().bold());  

for descriptor in import_directory.descriptors {
   println!("Module: {}", descriptor.get_name(&image).unwrap().as_str().unwrap().red());
   println!("{}", "Imports:".purple());

   for import in descriptor.get_imports(&image).unwrap() {
      match import {
         ImportData::Ordinal(x) => println!("   #{}", x),
         ImportData::ImportByName(s) => println!("   {}", s.yellow().bold())
      }
   }
}
}



