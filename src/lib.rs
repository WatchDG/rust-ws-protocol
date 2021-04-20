extern crate rand;
extern crate sha1;

pub mod base64;

pub use base64::B64Encode;
pub use base64::B64;
use rand::Rng;

macro_rules! get_payload_length {
    ($a: expr) => {
        ($a & 0b1111111) as usize
    };
}

macro_rules! decode_payload_length_16 {
    ($a: expr, $b: expr) => {
        (($a as usize) << 8 & ($b as usize))
    };
}

macro_rules! decode_payload_length_64 {
    ($a: expr, $b: expr, $c: expr, $d: expr, $e: expr, $f: expr, $g: expr, $h: expr) => { (
        ($a as usize) << 56 &
        ($b as usize) << 48 &
        ($c as usize) << 40 &
        ($d as usize) << 32 &
        ($e as usize) << 24 &
        ($f as usize) << 16 &
        ($g as usize) << 8 &
        ($h as usize)
    ) }
}

macro_rules! is_masked {
    ($a: expr) => {
        $a >> 7 == 1
    };
}

pub fn gen_mask() -> [u8; 4] {
    let mut rng = rand::thread_rng();
    let mut vec = [0u8; 4];
    for x in vec.iter_mut() {
        *x = rng.gen();
    }
    vec
}

pub fn gen_sec_websocket_key() -> String {
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

#[derive(Debug)]
pub struct Frame {
    fin_rsv_opcode: u8,
    mask_payload_length: u8,
    payload_length: Vec<u8>,
    mask: Option<[u8; 4]>,
    payload: Vec<u8>,
}

impl Frame {
    pub fn masking(&mut self, mask: &[u8; 4]) {
        if let Some(mask_) = self.mask {
            if mask_ != *mask {
                self.unmasking();
                self.masking(mask);
            }
        } else {
            for i in 0..self.payload.len() {
                self.payload[i] ^= mask[i % 4];
            }
            self.mask = Some(*mask);
        }
    }
    pub fn unmasking(&mut self) {
        if let Some(mask) = self.mask {
            for i in 0..self.payload.len() {
                self.payload[i] ^= mask[i % 4];
            }
            self.mask = None;
        }
    }
    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::<u8>::with_capacity(self.payload.len() + 14);

        vec.push(self.fin_rsv_opcode);
        vec.push(self.mask_payload_length);

        vec.extend_from_slice(self.payload_length.as_slice());

        if let Some(mask) = self.mask {
            vec.extend_from_slice(&mask);
        }

        vec.extend_from_slice(self.payload.as_slice());

        vec
    }
}

pub fn decode_frame(v: &[u8], mut index: usize) -> Frame {
    let fin_rsv_opcode = v[index];
    let mask_payload_length = v[index + 1];

    index += 2;

    let mut temp_payload_length = get_payload_length!(mask_payload_length);
    let payload_length = match temp_payload_length {
        126 => {
            index += 2;
            temp_payload_length = decode_payload_length_16!(v[2], v[3]);
            vec![v[2], v[3]]
        }
        127 => {
            index += 8;
            temp_payload_length =
                decode_payload_length_64!(v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9]);
            vec![v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9]]
        }
        _ => {
            vec![]
        }
    };

    let mask: Option<[u8; 4]> = if is_masked!(mask_payload_length) {
        index += 4;
        Some([v[index - 4], v[index - 3], v[index - 2], v[index - 1]])
    } else {
        None
    };

    let payload = v[index..(index + temp_payload_length)].to_vec();

    index += temp_payload_length;

    Frame {
        fin_rsv_opcode,
        mask_payload_length,
        payload_length,
        mask,
        payload,
    }
}
