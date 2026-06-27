use std::io::{self, BufRead, Write};

#[tokio::main]
async fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    let mut reader = stdin.lock();
    let mut line = String::new();

    while reader.read_line(&mut line)? > 0 {
        stdout.write_all(line.as_bytes())?;
        stdout.flush()?;
        line.clear();
    }

    Ok(())
}
