pub struct Args {
    pub all_flags: bool,
    pub expand_reloc: bool,
    pub file_path: String,
}

impl Args {
    pub fn parse() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let all_flags = args.iter().any(|a| a == "--all-flags");
        let expand_reloc = args.iter().any(|a| a == "-r");
        let positional: Vec<&String> = args
            .iter()
            .skip(1)
            .filter(|a| !a.starts_with("--") && !a.starts_with('-'))
            .collect();
        if positional.is_empty() {
            eprintln!("Usage: unwrapped [--all-flags] [-r] <file>");
            std::process::exit(1);
        }
        Args {
            all_flags,
            expand_reloc,
            file_path: positional[0].clone(),
        }
    }
}
