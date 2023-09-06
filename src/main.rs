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

fn main() {
	// Set 1 Challenge 1
	assert_eq!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
		num_to_base64(
			&hex_to_num("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap()
		)
	);
}
