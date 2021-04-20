const B64_ENCODE: [u8; 64] = [
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
    0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2b, 0x2f,
];

const B64_PAD: u8 = 0x3d;

pub struct B64<T>(T);

pub trait B64Encode<I, O> {
    fn encode(input: I) -> O;
}

impl B64Encode<&[u8], String> for B64<String> {
    fn encode(input: &[u8]) -> String {
        let bytes = input;
        let length = bytes.len();
        let mut vec = Vec::<u8>::with_capacity(length * 4 / 3);
        let mut index = 0;
        if length >= 3 {
            while index <= (length - 3) {
                let value = (bytes[index] as u32) << 16
                    | (bytes[index + 1] as u32) << 8
                    | (bytes[index + 2] as u32);
                vec.push(B64_ENCODE[((value >> 18) & 0b11_1111) as usize]);
                vec.push(B64_ENCODE[((value >> 12) & 0b11_1111) as usize]);
                vec.push(B64_ENCODE[((value >> 6) & 0b11_1111) as usize]);
                vec.push(B64_ENCODE[(value & 0b11_1111) as usize]);
                index += 3;
            }
        }
        match length - index {
            2 => {
                let value = (bytes[index] as u32) << 16 | (bytes[index + 1] as u32) << 8;
                vec.push(B64_ENCODE[((value >> 18) & 0b11_1111) as usize]);
                vec.push(B64_ENCODE[((value >> 12) & 0b11_1111) as usize]);
                vec.push(B64_ENCODE[((value >> 6) & 0b11_1111) as usize]);
                vec.push(B64_PAD);
            }
            1 => {
                let value = (bytes[index] as u32) << 16;
                vec.push(B64_ENCODE[((value >> 18) & 0b11_1111) as usize]);
                vec.push(B64_ENCODE[((value >> 12) & 0b11_1111) as usize]);
                vec.push(B64_PAD);
                vec.push(B64_PAD);
            }
            _ => {}
        };
        String::from_utf8(vec).unwrap()
    }
}
