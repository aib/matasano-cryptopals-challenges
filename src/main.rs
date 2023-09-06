#[derive(Debug)]
enum HexError {
	InvalidCharacter,
	OddLength,
}

struct Bytes {
	bytes: Vec<u8>,
}

impl Bytes {
	pub fn from_vec(bytes: Vec<u8>) -> Self {
		Self { bytes }
	}

	pub fn from_hex(hstr: &str) -> Result<Self, HexError> {
		hex::decode(hstr).map_err(|err| match err {
			hex::FromHexError::InvalidHexCharacter {..} => HexError::InvalidCharacter,
			hex::FromHexError::OddLength                => HexError::OddLength,
			hex::FromHexError::InvalidStringLength => panic!("Invalid error for hex::decode"),
		}).map(Self::from_vec)
	}

	pub fn hex(&self) -> String {
		hex::encode(&self.bytes)
	}

	pub fn base64(&self) -> String {
		use base64::Engine;
		base64::engine::general_purpose::STANDARD.encode(&self.bytes)
	}
}

fn xor(b1: &Bytes, b2: &Bytes) -> Bytes {
	let size = std::cmp::max(b1.bytes.len(), b2.bytes.len());
	let pad1 = b2.bytes.len().saturating_sub(b1.bytes.len());
	let pad2 = b1.bytes.len().saturating_sub(b2.bytes.len());

	let mut res = Vec::with_capacity(size);
	for i in 0..size {
		if i < pad1 {
			res.push(b2.bytes[i]);
		} else if i < pad2 {
			res.push(b1.bytes[i]);
		} else {
			res.push(b1.bytes[i - pad1] ^ b2.bytes[i - pad2]);
		}
	}
	Bytes::from_vec(res)
}

fn main() {
	{ // Set 1 Challenge 1
		let num = Bytes::from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
		assert_eq!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", num.base64());
		println!("Set 1 Challenge 1: {}", num.base64());
	}

	{ // Set 1 Challenge 2
		let res = xor(&Bytes::from_hex("1c0111001f010100061a024b53535009181c").unwrap(), &Bytes::from_hex("686974207468652062756c6c277320657965").unwrap());
		assert_eq!("746865206b696420646f6e277420706c6179", res.hex());
		println!("Set 1 Challenge 2: {}", res.hex());
	}
}
