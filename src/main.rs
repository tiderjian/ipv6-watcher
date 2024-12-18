use std::env;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use base64::{engine::general_purpose, Engine};
use regex::Regex;
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use reqwest::Client;
use sha2::Digest;
use hex;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

fn get_wifi_ipv6_address() -> Option<String> {
    let output = Command::new("powershell")
        .arg("-Command")
        .arg("ipconfig")
        .output()
        .expect("Failed to execute command");

    let result = String::from_utf8_lossy(&output.stdout);

    let re = Regex::new(r"\b2[0-9a-fA-F]{3}:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){6}\b").unwrap();

    for line in result.lines() {
        if line.contains("IPv6") {
            if let Some(captures) = re.captures(line) {
                return Some(captures[0].to_string());
            }
        }
    }

    None
}

fn encrypt_aes_256_cbc(plain_text: &str, key: &str) -> Result<String, anyhow::Error> {
    // Generate a SHA256 hash from the key and take the first 32 bytes
    let hash_key = hex::encode(sha2::Sha256::digest(key.as_bytes()));
    let en_key = &hash_key[0..32];

    // Use the first 16 bytes of the encryption key as the IV
    let iv = &en_key[0..16];

    // Create an AES-256-CBC cipher
    let cipher = Aes256Cbc::new_from_slices(en_key.as_bytes(), iv.as_bytes()).unwrap();

    // Encrypt and apply padding
    let cipher_text = cipher.encrypt_vec(plain_text.as_bytes());

    
    // Base64 encode the encrypted data
    Ok(general_purpose::STANDARD.encode(&cipher_text))
}

async fn send(content: String) -> Result<(), anyhow::Error> {
    let client = Client::builder().build().unwrap();
    let url = format!("{}/home/index/setIpv6", env::var("HOST").unwrap());
    client.post(url).form(&[("entext", &content)]).send().await?;
    Ok(())
}

fn current_time() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    dotenv::dotenv().ok();

    loop{
        let key = env::var("KEY").unwrap();
        match get_wifi_ipv6_address() {
            Some(ip) => {
                let text = format!(r#"{{"timestamp":{},"ipv6":"{}"}}"#, current_time(), ip);
                let en_text = encrypt_aes_256_cbc(&text, &key).unwrap();
                send(en_text).await?;
            }
            None => println!("No WiFi IPv6 address found."),
        }

        sleep(Duration::from_secs(5 * 60));
    }
}
