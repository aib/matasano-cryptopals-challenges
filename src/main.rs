#[derive(Debug)]
enum HexError {
	InvalidCharacter,
	OddLength,
}

type Number = Vec<u8>;

fn hex_to_num(hstr: &str) -> Result<Number, HexError> {
	hex::decode(hstr).map_err(|err| match err {
		hex::FromHexError::InvalidHexCharacter {..} => HexError::InvalidCharacter,
		hex::FromHexError::OddLength                => HexError::OddLength,
		hex::FromHexError::InvalidStringLength => panic!("Invalid error for hex::decode"),
	})
}

fn num_to_base64(num: &Number) -> String {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD.encode(num)
}

fn num_to_hex(num: &Number) -> String {
	hex::encode(num)
}

fn xor(num1: &Number, num2: &Number) -> Number {
	let size = std::cmp::max(num1.len(), num2.len());
	let pad1 = num2.len().saturating_sub(num1.len());
	let pad2 = num1.len().saturating_sub(num2.len());

	let mut res = Vec::with_capacity(size);
	for i in 0..size {
		if i < pad1 {
			res.push(num2[i]);
		} else if i < pad2 {
			res.push(num1[i]);
		} else {
			res.push(num1[i - pad1] ^ num2[i - pad2]);
		}
	}
	res
}

fn main() {
	// Set 1 Challenge 1
	assert_eq!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
		num_to_base64(
			&hex_to_num("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap()
		)
	);

	// Set 1 Challenge 2
	assert_eq!("746865206b696420646f6e277420706c6179",
		num_to_hex(&xor(
			&hex_to_num("1c0111001f010100061a024b53535009181c").unwrap(),
			&hex_to_num("686974207468652062756c6c277320657965").unwrap(),
		))
	)
}
