// Identical consumer source for both packages. Runtime input prevents a constant
// invalid input from removing the real parser at link time. This measures the
// linked parser consumer, not every exported library capability.
fn main() {
    let path = std::env::args_os()
        .nth(1)
        .expect("usage: consumer DEVICE_RESPONSE_CBOR");
    let bytes = std::fs::read(path).expect("read DeviceResponse");
    match mdoc::parse(&bytes) {
        Ok(response) => println!("documents={}", response.documents.len()),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}
