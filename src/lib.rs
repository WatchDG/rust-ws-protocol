extern crate rand;
extern crate sha1;

pub mod base64;

pub use base64::B64Encode;
pub use base64::B64;
use rand::Rng;

pub fn get_sec_websocket_key() -> String {
    let mut rng = rand::thread_rng();
    let mut vec = [0u8; 16];
    for x in vec.iter_mut() {
        *x = rng.gen();
    }
    B64::<String>::encode(&vec)
}

pub fn get_sec_websocket_accept(sec_web_socket_key: &str) -> String {
    let mut hash = sha1::Sha1::new();
    hash.update(
        (sec_web_socket_key.to_owned() + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
    );
    B64::<String>::encode(&hash.digest().bytes())
}
