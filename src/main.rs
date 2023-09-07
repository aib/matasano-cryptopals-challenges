use std::collections::HashMap;
use std::hash::Hash;

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

	pub fn to_string(&self) -> String {
		String::from_utf8_lossy(&self.bytes).into_owned()
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

fn xor_decode(ciphertext: &Bytes, key: &Bytes) -> Bytes {
	let size = ciphertext.bytes.len();
	let mut plaintext = Vec::with_capacity(size);
	for i in 0..size {
		plaintext.push(ciphertext.bytes[i] ^ key.bytes[i % key.bytes.len()]);
	}
	Bytes::from_vec(plaintext)
}

fn counts<T, I>(iterator: T) -> HashMap<I, usize>
where T: Iterator<Item=I>, I: Eq + Hash {
	let mut map = HashMap::new();
	for e in iterator {
		*map.entry(e).or_insert(0) += 1;
	}
	map
}

fn frequencies<T, I>(iterator: T) -> HashMap<I, f64>
where T: Iterator<Item=I>, I: Eq + Hash {
	let counts = counts(iterator);
	let total: usize = counts.iter().map(|(_, c)| c).sum();
	counts.into_iter()
		.map(|kv| (kv.0, kv.1 as f64 / total as f64))
		.collect()
}

fn score_text(text: &str) -> f64 {
	// From https://en.wikipedia.org/wiki/Letter_frequency
	let english_freqs = HashMap::from([
		('a', 0.08200),
		('b', 0.01500),
		('c', 0.02800),
		('d', 0.04300),
		('e', 0.12700),
		('f', 0.02200),
		('g', 0.02000),
		('h', 0.06100),
		('i', 0.07000),
		('j', 0.00150),
		('k', 0.00770),
		('l', 0.04000),
		('m', 0.02400),
		('n', 0.06700),
		('o', 0.07500),
		('p', 0.01900),
		('q', 0.00095),
		('r', 0.06000),
		('s', 0.06300),
		('t', 0.09100),
		('u', 0.02800),
		('v', 0.00980),
		('w', 0.02400),
		('x', 0.00150),
		('y', 0.02000),
		('z', 0.00074),
	]);

	let text_lower = text.to_lowercase();
	let freqs = frequencies(text_lower.chars());

	let mut score = 0.0;
	for (c, f) in freqs {
		if c == ' ' { continue; }
		let fscore = english_freqs.get(&c)
			.map(|ef| ef * f * (1.0 - (ef - f).abs().sqrt()))
			.unwrap_or(f * f * -1.0);
		score += fscore;
	}

	score
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

	{ // Set 1 Challenge 3
		let ciphertext = Bytes::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
		let mut scored = (0..=255).map(|key| {
			let plaintext = xor_decode(&ciphertext, &Bytes::from_vec(vec![key])).to_string();
			let score = score_text(&plaintext);
			(key, plaintext, score)
		}).collect::<Vec<_>>();
		scored.sort_by(|kts1, kts2| kts1.2.partial_cmp(&kts2.2).unwrap().reverse());
		let best = scored.get(0).unwrap();
		println!("Set 1 Challenge 3: {} (key=0x{:02x})", best.1, best.0);
	}
}
