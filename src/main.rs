use std::error::Error;

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut mychain = aphrodite::BlockFile::new("./block.chain");

    let mut email = aphrodite::Block::null();

    email.to(aphrodite::Addr::new(13));
    email.from(aphrodite::Addr::new(17));
    email.message_str("hdafihjouefwjouaehdafihjouefwjouaehdafihjouefwjouaehdafihjouefwjouae");
    
    let mut rng = rand::thread_rng();

    let bits = 2048;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = rsa::RsaPublicKey::from(&private_key);

    mychain.append_enc(&email, public_key);

    let read = mychain.read_enc(private_key, 0);

    println!("{:?}", std::str::from_utf8(&read));

    Ok(())
}