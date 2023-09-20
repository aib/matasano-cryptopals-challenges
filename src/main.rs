use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use indexmap::IndexMap;

fn bytes_from_hex(hstr: &str) -> Vec<u8> {
	hex::decode(hstr).expect("Error decoding hex")
}

fn bytes_from_base64(estr: &str) -> Vec<u8> {
	use base64::Engine;
	let stripped: String = estr.chars().filter(|c| !c.is_whitespace()).collect();
	base64::engine::general_purpose::STANDARD.decode(stripped)
		.expect("Error decoding base64")
}

fn bytes_from_str(s: &str) -> Vec<u8> {
	s.to_owned().into_bytes()
}

fn bytes_to_hex(bs: &[u8]) -> String {
	hex::encode(bs)
}

fn bytes_to_base64(bs: &[u8]) -> String {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD.encode(bs)
}

fn bytes_to_string(bs: &[u8]) -> String {
	String::from_utf8_lossy(bs).into_owned()
}

fn bytes_to_safe_string(bs: &[u8]) -> String {
	bytes_to_string(bs).chars().map(|c| if c == ' ' || c.is_ascii_graphic() { c } else { '?' }).collect()
}

fn bytes_to_summary(bs: &[u8]) -> String {
	let s = bytes_to_string(bs);
	let lines: Vec<_> = s.lines().collect();
	format!("{} ({} lines(s), {} char(s), SHA256: {})", lines[0].trim(), lines.len(), s.len(), sha256str(bs))
}

fn sha256str(bs: &[u8]) -> String {
	let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), bs)
		.expect("Unable to hash");
	bytes_to_hex(&digest)
}

fn get_random_bytes(size: usize) -> Vec<u8> {
	use rand::RngCore;
	let mut v = vec![0; size];
	rand::thread_rng().fill_bytes(&mut v);
	v
}

fn get_nth_block(bytes: &[u8], block_size: usize, n: usize) -> &[u8] {
	let block_offset = n * block_size;
	&bytes[usize::min(block_offset, bytes.len()) .. usize::min(block_offset + block_size, bytes.len())]
}

fn xor(b1: &[u8], b2: &[u8]) -> Vec<u8> {
	let size = std::cmp::max(b1.len(), b2.len());
	let pad1 = b2.len().saturating_sub(b1.len());
	let pad2 = b1.len().saturating_sub(b2.len());

	let mut res = Vec::with_capacity(size);
	for i in 0..size {
		if i < pad1 {
			res.push(b2[i]);
		} else if i < pad2 {
			res.push(b1[i]);
		} else {
			res.push(b1[i - pad1] ^ b2[i - pad2]);
		}
	}
	res
}

fn xor_encode(text: &[u8], key: &[u8]) -> Vec<u8> {
	let size = text.len();
	let mut encoded = Vec::with_capacity(size);
	for i in 0..size {
		encoded.push(text[i] ^ key[i % key.len()]);
	}
	encoded
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
	let total: usize = counts.values().sum();
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

fn hamming_distance(str1: &[u8], str2: &[u8]) -> usize {
	let mut distance = 0;
	for (b1, b2) in std::iter::zip(str1, str2) {
		distance += (b1 ^ b2).count_ones() as usize;
	}
	distance
}

fn chunked_average_distance(slice: &[u8], chunk_size: usize) -> f64 {
	let blocks: Vec<&[u8]> = slice.chunks(chunk_size).collect();
	let mut total_distance = 0.0;
	let mut num_comparisons = 0;
	for i in 0..blocks.len() {
		let block1 = blocks[i];
		for j in (i+1)..blocks.len() {
			let block2 = blocks[j];
			total_distance += hamming_distance(block1, block2) as f64 / usize::min(block1.len(), block2.len()) as f64;
			num_comparisons += 1
		}
	}
	total_distance / num_comparisons as f64
}

fn count_duplicate_blocks(bytes: &[u8], block_size: usize) -> usize {
	let mut blocks = HashSet::new();
	let mut duplicates = 0;
	for block in bytes.chunks(block_size) {
		if !blocks.insert(block) {
			duplicates += 1;
		}
	}
	duplicates
}

fn solve_xor<F: FnMut(&str) -> f64>(ciphertext: &[u8], keysize: usize, mut scorer: F) -> (Vec<u8>, Vec<u8>, f64) {
	if keysize == 0 {
		return (vec![], vec![], scorer(""));
	}

	fn all_keys(size: usize) -> Vec<Vec<u8>> {
		if size == 0 {
			vec!(vec!())
		} else {
			all_keys(size - 1).iter()
				.flat_map(|k| (0..=255).map(|n| {
					let mut k2 = k.clone();
					k2.push(n);
					k2
				}))
				.collect()
		}
	}

	let mut scored: Vec<_> = all_keys(keysize).into_iter().map(|key| {
		let plaintext = xor_encode(ciphertext, &key);
		let score = scorer(&bytes_to_string(&plaintext));
		(key, plaintext, score)
	}).collect();
	scored.sort_by(|kts1, kts2| kts1.2.total_cmp(&kts2.2));

	let (key, plaintext, score) = scored.pop().unwrap();
	(key, plaintext, score)
}

fn pkcs7_pad(bytes: &[u8], size: usize) -> Vec<u8> {
	let pad = size.saturating_sub(bytes.len());
	let mut vec = bytes.to_vec();
	for _ in 0..pad {
		vec.push(pad as u8);
	}
	vec
}

fn pkcs7_unpad(bytes: &[u8]) -> Option<Vec<u8>> {
	let pad = *bytes.last()?;
	if pad == 0 {
		return None;
	}

	let mut vec = bytes.to_vec();
	for _ in 0..pad {
		let b = vec.pop()?;
		if b != pad {
			return None;
		}
	}
	Some(vec)
}

fn pkcs7_pad_to_block_size(bytes: &[u8], block_size: usize) -> Vec<u8> {
	let pad = block_size - (bytes.len() % block_size);
	pkcs7_pad(bytes, bytes.len() + pad)
}

fn pkcs7_unpad_in_place(bytes: &mut Vec<u8>) {
	let pad = bytes[bytes.len() - 1].into();
	bytes.truncate(bytes.len().saturating_sub(pad));
}

fn aes_128_encrypt_block(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
	use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
	let cipher = aes::Aes128::new(key.into());
	let mut block = GenericArray::clone_from_slice(plaintext);
	cipher.encrypt_block(&mut block);
	block.to_vec()
}

fn aes_128_decrypt_block(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
	use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
	let cipher = aes::Aes128::new(key.into());
	let mut block = GenericArray::clone_from_slice(ciphertext);
	cipher.decrypt_block(&mut block);
	block.to_vec()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlockMode {
	ECB,
	CBC
}

fn ecb_encrypt<E>(mut enc: E, block_size: usize, key: &[u8], plaintext: &[u8]) -> Vec<u8>
where E: FnMut(&[u8], &[u8]) -> Vec<u8> {
	let padded = pkcs7_pad_to_block_size(plaintext, block_size);
	let mut res = Vec::with_capacity(padded.len());
	for ptb in padded.chunks(block_size) {
		res.extend(&enc(key, ptb));
	}
	res
}

fn ecb_decrypt<D>(mut dec: D, block_size: usize, key: &[u8], ciphertext: &[u8]) -> Vec<u8>
where D: FnMut(&[u8], &[u8]) -> Vec<u8> {
	let mut res = Vec::with_capacity(ciphertext.len());
	for ptb in ciphertext.chunks(block_size) {
		res.extend(&dec(key, ptb));
	}
	pkcs7_unpad_in_place(&mut res);
	res
}

fn cbc_encrypt<E>(mut enc: E, block_size: usize, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8>
where E: FnMut(&[u8], &[u8]) -> Vec<u8> {
	let padded = pkcs7_pad_to_block_size(plaintext, block_size);
	let mut res = Vec::with_capacity(padded.len());
	let mut iv = iv.to_vec();

	for ptb in padded.chunks(block_size) {
		let xored = xor_encode(ptb, &iv);
		let eout = enc(key, &xored);
		res.extend(&eout);
		iv = eout;
	}
	res
}

fn cbc_decrypt_no_unpad<D>(mut dec: D, block_size: usize, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8>
where D: FnMut(&[u8], &[u8]) -> Vec<u8> {
	let mut res = Vec::with_capacity(ciphertext.len());
	let mut iv = iv.clone();

	for ctb in ciphertext.chunks(block_size) {
		let bdec = dec(key, ctb);
		let xordec = xor_encode(&bdec, &iv);
		res.extend(xordec);
		iv = ctb;
	}
	res
}

fn cbc_decrypt<D>(dec: D, block_size: usize, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8>
where D: FnMut(&[u8], &[u8]) -> Vec<u8> {
	let mut res = cbc_decrypt_no_unpad(dec, block_size, key, iv, ciphertext);
	pkcs7_unpad_in_place(&mut res);
	res
}

fn cbc_decrypt_check_pad<D>(dec: D, block_size: usize, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>>
where D: FnMut(&[u8], &[u8]) -> Vec<u8> {
	let res = cbc_decrypt_no_unpad(dec, block_size, key, iv, ciphertext);
	pkcs7_unpad(&res)
}

fn ctr_encrypt<E>(mut enc: E, block_size: usize, key: &[u8], nonce: &[u8], text: &[u8]) -> Vec<u8>
where E: FnMut(&[u8], &[u8]) -> Vec<u8> {
	assert!(nonce.len() == block_size - 8, "Nonce must be {} bytes", block_size - 8);

	let mut ctr: u64 = 0;
	let mut out = Vec::with_capacity(text.len());

	for chunk in text.chunks(block_size) {
		let ctr_block = [nonce, &ctr.to_le_bytes()].concat();
		let eout = enc(key, &ctr_block);
		out.extend(&xor_encode(&chunk, &eout));
		ctr += 1;
	}

	out
}

fn encryption_oracle(input: &[u8]) -> (BlockMode, Vec<u8>) {
	use rand::Rng;
	let mut rng = rand::thread_rng();

	let key = rng.gen::<[u8; 16]>();
	let prefix = get_random_bytes(rng.gen_range(1..=16));
	let postfix = get_random_bytes(rng.gen_range(1..=16));
	let plaintext = [&prefix, input, &postfix].concat();

	match rng.gen::<bool>() {
		false => {
			(BlockMode::ECB, ecb_encrypt(aes_128_encrypt_block, 16, &key, &plaintext))
		}
		true => {
			let iv = get_random_bytes(16);
			(BlockMode::CBC, cbc_encrypt(aes_128_encrypt_block, 16, &key, &iv, &plaintext))
		}
	}
}

fn detect_output_size_change<F>(mut processor: F) -> (usize, usize, usize)
where F: FnMut(&[u8]) -> Vec<u8> {
	let mut input = Vec::new();
	let mut last_size = None;
	loop {
		let ct = processor(&input);
		let new_size = ct.len();
		if let Some(ls) = last_size {
			if new_size != ls {
				return (ls, new_size, input.len());
			}
		}
		last_size = Some(new_size);
		input.push(0);
	}
}

fn detection_oracle<F>(bbox: F) -> BlockMode
where F: FnOnce(&[u8]) -> Vec<u8> {
	let carefully_crafted_input = vec![
		01, 02, 03, 04, 05, 06, 07, 08, 09, 10, 11, 12, 13, 14, 15, 16,
		01, 02, 03, 04, 05, 06, 07, 08, 09, 10, 11, 12, 13, 14, 15, 16,
		01, 02, 03, 04, 05, 06, 07, 08, 09, 10, 11, 12, 13, 14, 15, 16,
		01, 02, 03, 04, 05, 06, 07, 08, 09, 10, 11, 12, 13, 14, 15, 16,
	];

	let ct = bbox(&carefully_crafted_input);

	if count_duplicate_blocks(&ct, 16) >= 2 {
		BlockMode::ECB
	} else {
		BlockMode::CBC
	}
}

fn determine_encryptor_block_size<E>(enc: E) -> usize
where E: FnMut(&[u8]) -> Vec<u8> {
	let (old, new, _) = detect_output_size_change(enc);
	new - old
}

fn solve_ecb_postfix<F>(ecb: F, block_size: usize) -> Vec<u8>
where F: FnMut(&[u8]) -> Vec<u8> {
	return solve_ecb_postfix_with_prefix(ecb, block_size, 0);
}

fn solve_ecb_postfix_with_prefix<F>(mut ecb: F, block_size: usize, prefix_len: usize) -> Vec<u8>
where F: FnMut(&[u8]) -> Vec<u8> {
	assert!(block_size > 0, "block_size is 0");

	let mut known_postfix = Vec::new();

	let mut get_next_byte = |block_size: usize, known_postfix: &[u8]| -> Option<u8> {
		let prepad: Vec<u8> = vec![0; block_size - (prefix_len % block_size)];
		let zeroes = vec![0; block_size - (known_postfix.len() % block_size) - 1];

		let output_block_num = (prefix_len + prepad.len() + zeroes.len() + known_postfix.len()) / block_size;

		let mut crafted_block = [&prepad, &zeroes, known_postfix, &[0]].concat();
		let next_byte_offset = prepad.len() + zeroes.len() + known_postfix.len();

		let encmap: HashMap<Vec<u8>, u8> = HashMap::from_iter(
			(0..=255).map(|b| {
				crafted_block[next_byte_offset] = b;
				let enc = ecb(&crafted_block);
				(get_nth_block(&enc, block_size, output_block_num).to_vec(), b)
			})
		);
		let input_block: Vec<u8> = [&prepad[..], &zeroes].concat();
		let enc = ecb(&input_block);
		encmap.get(get_nth_block(&enc, block_size, output_block_num)).copied()
	};

	while let Some(next_byte) = get_next_byte(block_size, &known_postfix) {
		known_postfix.push(next_byte);
	}

	known_postfix.pop(); // We always end up with padding
	known_postfix
}

fn determine_prefix_length<F>(mut ecb: F, block_size: usize) -> usize
where F: FnMut(&[u8]) -> Vec<u8> {
	let mut indicator = Vec::new();
	let mut last_first_diff_block = None;

	for _ in 0..block_size+1 {
		indicator.push(0);

		let ilen = indicator.len();
		indicator[ilen - 1] = 0;
		let ct1 = ecb(&indicator);
		indicator[ilen - 1] = 0xff;
		let ct2 = ecb(&indicator);

		let cur_first_diff_block = std::iter::zip(ct1.chunks(block_size), ct2.chunks(block_size))
			.take_while(|(b1, b2)| b1 == b2)
			.count();

		if let Some(last) = last_first_diff_block {
			if last != cur_first_diff_block {
				return (last * block_size) + block_size + 1 - ilen;
			}
		}
		last_first_diff_block = Some(cur_first_diff_block);
	}
	panic!("Ciphertext block did not change after {} iterations. Wrong block size?", block_size+1)
}

fn solve_ecb_postfix_harder<F>(mut ecb: F, block_size: usize) -> Vec<u8>
where F: FnMut(&[u8]) -> Vec<u8> {
	let prefix_length = determine_prefix_length(&mut ecb, block_size);
	solve_ecb_postfix_with_prefix(&mut ecb, block_size, prefix_length)
}

fn parse_kv(kv_str: &str) -> IndexMap<String, String> {
	let mut map = IndexMap::new();
	for kv in kv_str.split("&") {
		if let Some(i) = kv.find("=") {
			let (k, v) = (&kv[0..i], &kv[i+1..]);
			map.insert(k.to_owned(), v.to_owned());
		}
	}
	map
}

fn encode_kv(kvm: &IndexMap<String, String>) -> String {
	kvm.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("&")
}

fn profile_for(email: &str) -> IndexMap<String, String> {
	let email = email.replace("=", "").replace("&", "");

	IndexMap::from([
		(String::from("email"), email),
		(String::from("uid"), String::from("10")),
		(String::from("role"), String::from("user")),
	])
}

fn solve_profile_generator<F>(mut bbox: F) -> Vec<u8>
where F: FnMut(&str) -> Vec<u8> {
	// Note: This assumes we know the original and target plaintext, the section to change is at the end, and we can use PKCS#7 padding in the e-mail

	// email=foo@bar.com&uid=10&role=user -> email=foo@bar.com&uid=10&role=admin
	// 0123456789abcdef0123456789abcdef01    0123456789abcdef0123456789abcdef012
	let email_prefix = b"blockalign"; // anything 10 bytes
	let admin_block = pkcs7_pad_to_block_size(b"admin", 16);

	let email = bytes_to_string(&[email_prefix.as_slice(), &admin_block].concat());
	let admin_block_enc = get_nth_block(&bbox(&email), 16, 1).to_vec();

	let aligning_email = bytes_to_string(b"foo+a@bar.com");
	let aligned_profile_enc = bbox(&aligning_email);
	let other_blocks_enc = &aligned_profile_enc[0..32];

	[other_blocks_enc, &admin_block_enc].concat()
}

fn solve_cbc_with_bitflip<F>(mut cbc: F) -> Vec<u8>
where F: FnMut(&[u8]) -> Vec<u8> {
	let almost = b"nodata:admin=true".to_vec();
	let mut almost_enc = cbc(&almost);
	almost_enc[22] ^= 1;
	almost_enc
}

fn solve_cbc_with_padding_oracle<O>(mut check_padding: O, iv: &[u8], ciphertext: &[u8]) -> Vec<u8>
where O: FnMut(&[u8], &[u8]) -> bool {
	#[derive(Clone)]
	struct Input {
		iv: Vec<u8>,
		ct: Vec<u8>,
	}

	impl Input {
		fn get_byte_for_output(&self, output_offset: usize) -> u8 {
			if output_offset < 16 {
				self.iv[output_offset]
			} else {
				self.ct[output_offset - 16]
			}
		}

		fn set_byte_for_output(&mut self, output_offset: usize, bval: u8) {
			if output_offset < 16 {
				self.iv[output_offset] = bval;
			} else {
				self.ct[output_offset - 16] = bval;
			}
		}

		fn change_byte_for_output<F>(&mut self, output_offset: usize, mutator: F)
		where F: FnOnce(u8) -> u8 {
			self.set_byte_for_output(output_offset, mutator(self.get_byte_for_output(output_offset)));
		}
	}

	let mut known_end = vec![];

	let mut get_next_byte = |known_end: &[u8]| {
		if known_end.len() >= ciphertext.len() {
			return None;
		}

		let ct_cutoff = ciphertext.len() - (known_end.len() / 16) * 16;
		let mut work_input = Input {
			iv: iv.to_vec(),
			ct: ciphertext[..ct_cutoff].to_vec()
		};
		let pad_len = (known_end.len() % 16) + 1;

		let ke_cutoff = known_end.len() % 16;
		for (i, k) in known_end[..ke_cutoff].iter().enumerate() {
			work_input.change_byte_for_output(ciphertext.len() - known_end.len() + i, |b| b ^ k ^ pad_len as u8);
		}

		let work_offset = ciphertext.len() - known_end.len() - 1;
		for b in 0..=255 {
			let mut last_changed = work_input.clone();
			last_changed.set_byte_for_output(work_offset, b);

			if check_padding(&last_changed.iv, &last_changed.ct) {
				if pad_len > 1 || {
					let mut penultimate_changed = last_changed.clone();
					penultimate_changed.change_byte_for_output(work_offset - 1, |b| b ^ 0xff);
					check_padding(&penultimate_changed.iv, &penultimate_changed.ct)
				} {
					return Some(work_input.get_byte_for_output(work_offset) ^ b ^ pad_len as u8);
				}
			}
		}
		None
	};

	while let Some(b) = get_next_byte(&known_end) {
		known_end.insert(0, b);
	}

	pkcs7_unpad_in_place(&mut known_end);
	known_end
}

fn main() {
	{ // Set 1 Challenge 1
		let num = bytes_from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
		assert_eq!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", bytes_to_base64(&num));
		println!("Set 1 Challenge 1: {}", bytes_to_base64(&num));
	}

	{ // Set 1 Challenge 2
		let res = xor(&bytes_from_hex("1c0111001f010100061a024b53535009181c"), &bytes_from_hex("686974207468652062756c6c277320657965"));
		assert_eq!("746865206b696420646f6e277420706c6179", bytes_to_hex(&res));
		println!("Set 1 Challenge 2: {}", bytes_to_hex(&res));
	}

	{ // Set 1 Challenge 3
		let ciphertext = bytes_from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
		let (key, text, _score) = solve_xor(&ciphertext, 1, score_text);
		println!("Set 1 Challenge 3: {} (key 0x{})", bytes_to_summary(&text), bytes_to_hex(&key));
	}

	{ // Set 1 Challenge 4
		let f = std::fs::read_to_string("4.txt").unwrap();
		let mut scored: Vec<_> = f.lines()
			.map(bytes_from_hex)
			.enumerate().map(|(line_no, line)| (line_no, solve_xor(&line, 1, score_text)))
			.collect();
		scored.sort_by(|l_kts1, l_kts2| l_kts1.1.2.total_cmp(&l_kts2.1.2));
		let (line_no, (key, text, _score)) = scored.pop().unwrap();
		println!("Set 1 Challenge 4: {} (line {}, key 0x{})", bytes_to_summary(&text), line_no + 1, bytes_to_hex(&key));
	}

	{ // Set 1 Challenge 5
		let plaintext = bytes_from_str("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
		let key = bytes_from_str("ICE");
		let ciphertext = xor_encode(&plaintext, &key);
		println!("Set 1 Challenge 5: {}", bytes_to_hex(&ciphertext));
		assert_eq!("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", bytes_to_hex(&ciphertext));
	}

	{ // Set 1 Challenge 6
		assert_eq!(37, hamming_distance(&bytes_from_str("this is a test"), &bytes_from_str("wokka wokka!!!")));
		let bs = bytes_from_base64(&std::fs::read_to_string("6.txt").unwrap());
		let mut keysize_dists: Vec<_> = (2..=40)
			.map(|keysize| (keysize, chunked_average_distance(&bs, keysize)))
			.collect();
		keysize_dists.sort_by(|kd1, kd2| kd1.1.total_cmp(&kd2.1).reverse());
		let probable_keysize = keysize_dists.pop().unwrap().0;

		let blocks: Vec<Vec<u8>> = bs.chunks(probable_keysize).map(|c| c.to_owned()).collect();
		let transposed: Vec<_> = (0..probable_keysize).map(|n| {
			let vslice: Vec<u8> = blocks.iter().filter_map(|b| b.get(n).copied()).collect();
			let (key, text, _score) = solve_xor(&vslice, 1, score_text);
			(key, text)
		}).collect();
		let (key_t, text_t): (Vec<Vec<u8>>, Vec<Vec<u8>>) = transposed.into_iter().unzip();

		let key: Vec<u8> = key_t.into_iter().flatten().collect();
		let text = (0..)
			.map(|n| text_t.iter().filter_map(|t| t.get(n).copied()).collect::<Vec<_>>())
			.take_while(|b| !b.is_empty())
			.flatten()
			.collect::<Vec<_>>();

		println!("Set 1 Challenge 6: {} (key 0x{})", bytes_to_summary(&text), bytes_to_hex(&key));
		assert_eq!("24df84533fc2778495577c844bcf3fe1d4d17c68d8c5cbc5a308286db58c69b6", sha256str(&text));
	}

	{ // Set 1 Challenge 7
		let bs = bytes_from_base64(&std::fs::read_to_string("7.txt").unwrap());
		let cipher = openssl::symm::Cipher::aes_128_ecb();

		let res = openssl::symm::decrypt(cipher, b"YELLOW SUBMARINE", None, &bs).unwrap();
		println!("Set 1 Challenge 7: {}", bytes_to_summary(&res));
		assert_eq!("24df84533fc2778495577c844bcf3fe1d4d17c68d8c5cbc5a308286db58c69b6", sha256str(&res));
	}

	{ // Set 1 Challenge 8
		let cts: Vec<Vec<u8>> = std::fs::read_to_string("8.txt").unwrap().lines().map(bytes_from_hex).collect();

		let mut ct_distances: Vec<_> = cts.iter()
			.map(|ct| (ct, chunked_average_distance(ct, 16)))
			.collect();

		ct_distances.sort_by(|ct_d1, ct_d2| ct_d1.1.total_cmp(&ct_d2.1).reverse());
		let (ct, _distance) = ct_distances.pop().unwrap();
		println!("Set 1 Challenge 8: {}?", sha256str(ct));
	}

	{ // Set 2 Challenge 9
		let padded = pkcs7_pad(b"YELLOW SUBMARINE", 20);
		println!("Set 2 Challenge 9: {}", bytes_to_hex(&padded));
		assert_eq!(b"YELLOW SUBMARINE\x04\x04\x04\x04".as_ref(), padded);
	}

	{ // Set 2 Challenge 10
		let ciphertext = bytes_from_base64(&std::fs::read_to_string("10.txt").unwrap());
		let dec = cbc_decrypt(aes_128_decrypt_block, 16, b"YELLOW SUBMARINE", &[0; 16], &ciphertext);
		println!("Set 2 Challenge 10: {}", bytes_to_summary(&dec));
		assert_eq!("24df84533fc2778495577c844bcf3fe1d4d17c68d8c5cbc5a308286db58c69b6", sha256str(&dec));
	}

	{ // Test ECB
		use rand::Rng;
		let mut rng = rand::thread_rng();

		let msg = bytes_from_str("We all live in a yellow submarine");
		let key = rng.gen::<[u8;16]>();
		let enc = ecb_encrypt(aes_128_encrypt_block, 16, &key, &msg);
		let dec = ecb_decrypt(aes_128_decrypt_block, 16, &key, &enc);
		assert_eq!(msg, dec);
	}

	{ // Test CBC
		use rand::Rng;
		let mut rng = rand::thread_rng();

		let msg = bytes_from_str("We all live in a yellow submarine");
		let key = rng.gen::<[u8;16]>();
		let iv  = rng.gen::<[u8;16]>();
		let enc = cbc_encrypt(aes_128_encrypt_block, 16, &key, &iv, &msg);
		let dec = cbc_decrypt(aes_128_decrypt_block, 16, &key, &iv, &enc);
		assert_eq!(msg, dec);
	}

	{ // Set 2 Challenge 11
		let iterations = 100;
		let mut correct = 0;
		for _ in 0..iterations {
			let mut actual_mode = None;
			let bbox = |input: &[u8]| {
				let (mode, ct) = encryption_oracle(input);
				actual_mode = Some(mode);
				ct
			};

			let detected_mode = detection_oracle(bbox);
			if actual_mode.is_some_and(|m| detected_mode == m) {
				correct += 1;
			}
		}
		println!("Set 2 Challenge 11: {}/{}", correct, iterations);
		assert!(correct as f64 / iterations as f64 > 0.8);
	}

	{ // Set 2 Challenge 12
		let unknown_string = bytes_from_base64(concat!(
			"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg",
			"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq",
			"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg",
			"YnkK",
		));
		let unknown_key = get_random_bytes(16);
		let encryptor = |prefix: &[u8]| {
			let plaintext = [prefix, &unknown_string].concat();
			ecb_encrypt(aes_128_encrypt_block, 16, &unknown_key, &plaintext)
		};

		let block_size = determine_encryptor_block_size(encryptor);
		assert_eq!(16, block_size);

		let block_mode = detection_oracle(encryptor);
		assert_eq!(BlockMode::ECB, block_mode);

		let res = solve_ecb_postfix(encryptor, block_size);
		println!("Set 2 Challenge 12: {}", bytes_to_summary(&res));
		assert_eq!("b773748567cdff19e6a1a3bca9cb2c824568b06bfeeba026e82771a9c5307dc0", sha256str(&res));
	}

	{ // Set 2 Challenge 13
		let parsed = parse_kv("foo=bar&baz=qux&zap=zazzle");
		assert_eq!(
			IndexMap::from([
				(String::from("foo"), String::from("bar")),
				(String::from("baz"), String::from("qux")),
				(String::from("zap"), String::from("zazzle")),
			]),
			parsed
		);
		let user = profile_for("foo@bar.com");
		assert_eq!("email=foo@bar.com&uid=10&role=user", encode_kv(&user));
		let unknown_key = get_random_bytes(16);
		let profile_oracle = |email: &str| {
			ecb_encrypt(aes_128_encrypt_block, 16, &unknown_key, &bytes_from_str(&encode_kv(&profile_for(email))))
		};
		let res_ct = solve_profile_generator(profile_oracle);
		let res_str = bytes_to_string(&ecb_decrypt(aes_128_decrypt_block, 16, &unknown_key, &res_ct));
		println!("Set 2 Challenge 13: {}", res_str);
		assert_eq!(Some(&String::from("admin")), parse_kv(&res_str).get("role"));
	}

	{ // Set 2 Challenge 14
		let unknown_string = bytes_from_base64(concat!(
			"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg",
			"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq",
			"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg",
			"YnkK",
		));
		let unknown_key = get_random_bytes(16);
		let random_prefix = {
			use rand::{Rng, RngCore};
			let mut v = vec![0; rand::thread_rng().gen_range(0..=32)];
			rand::thread_rng().fill_bytes(&mut v);
			v
		};
		let encryptor = |attacker_controlled: &[u8]| {
			let plaintext = [&random_prefix, attacker_controlled, &unknown_string].concat();
			ecb_encrypt(aes_128_encrypt_block, 16, &unknown_key, &plaintext)
		};
		let res = solve_ecb_postfix_harder(encryptor, 16);
		println!("Set 2 Challenge 14: {}", bytes_to_summary(&res));
		assert_eq!("b773748567cdff19e6a1a3bca9cb2c824568b06bfeeba026e82771a9c5307dc0", sha256str(&res));
	}

	{ // Set 2 Challenge 15
		let res = pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04").unwrap();
		println!("Set 2 Challenge 15: {}", bytes_to_string(&res));
		assert_eq!(b"ICE ICE BABY".to_vec(), res);

		assert_eq!(None, pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05"));
		assert_eq!(None, pkcs7_unpad(b"ICE ICE BABY\x01\x02\x03\x04"));
	}

	{ // Set 2 Challenge 16
		let key = get_random_bytes(16);
		let iv = get_random_bytes(16);
		let encryptor = |userdata: &[u8]| {
			let escaped = bytes_to_string(userdata)
				.replace("\\", "\\\\").replace(";", "\\;").replace("\"", "\\\"");
			let s = format!("comment1=cooking%20MCs;userdata={};comment2=%20like%20a%20pound%20of%20bacon", escaped);
			cbc_encrypt(aes_128_encrypt_block, 16, &key, &iv, &bytes_from_str(&s))
		};
		let decryptor = |ciphertext: &[u8]| {
			cbc_decrypt(aes_128_decrypt_block, 16, &key, &iv, ciphertext)
		};
		let res = solve_cbc_with_bitflip(encryptor);
		let dec = decryptor(&res);
		println!("Set 2 Challenge 16: {}", bytes_to_safe_string(&dec));
		assert!(bytes_to_string(&dec).contains(";admin=true;"));
	}

	{ // Set 3 Challenge 17
		let key = get_random_bytes(16);
		let encryptor = |plaintext: &[u8]| {
			let iv = get_random_bytes(16);
			let ct = cbc_encrypt(aes_128_encrypt_block, 16, &key, &iv, plaintext);
			(iv, ct)
		};
		let oracle = |iv: &[u8], ciphertext: &[u8]| {
			cbc_decrypt_check_pad(aes_128_decrypt_block, 16, &key, iv, ciphertext).is_some()
		};
		let strings = vec![
			"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
			"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
			"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
			"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
			"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
			"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
			"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
			"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
			"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
			"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
		];
		let chosen_string = bytes_from_str(&{
			use rand::seq::SliceRandom;
			strings.choose(&mut rand::thread_rng()).unwrap()
		});
		let (iv, ct) = encryptor(&chosen_string);
		let res = solve_cbc_with_padding_oracle(oracle, &iv, &ct);
		println!("Set 3 Challenge 17: {}", bytes_to_string(&bytes_from_base64(&bytes_to_string(&res))));
		assert_eq!(chosen_string, res);
	}

	{ // Set 3 Challenge 18
		let string = bytes_from_base64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
		let dec = ctr_encrypt(aes_128_encrypt_block, 16, b"YELLOW SUBMARINE", &vec![0; 8], &string);
		println!("Set 3 Challenge 18: {}", bytes_to_string(&dec));
		assert_eq!("0e15ad04b165a34e8fe2dea7f9dda0a128b03c86d913a1dc8fb34272e436a2bc", sha256str(&dec));
	}

	{ // Set 3 Challenge 19
		let strings = [
			"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
			"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
			"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
			"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
			"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
			"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
			"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
			"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
			"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
			"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
			"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
			"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
			"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
			"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
			"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
			"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
			"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
			"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
			"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
			"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
			"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
			"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
			"U2hlIHJvZGUgdG8gaGFycmllcnM/",
			"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
			"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
			"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
			"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
			"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
			"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
			"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
			"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
			"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
			"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
			"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
			"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
			"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
			"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
			"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
			"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
			"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		].iter().map(|s| bytes_from_base64(&s)).collect::<Vec<_>>();

		let key = get_random_bytes(16);
		let ciphertexts = strings.iter()
			.map(|pt| ctr_encrypt(aes_128_encrypt_block, 16, &key, &vec![0; 8], pt))
			.collect::<Vec<_>>();

		let transposed = (0..)
			.map(|n| {
				ciphertexts.iter().filter_map(|c| c.get(n).copied()).collect()
			})
			.take_while(|t: &Vec<u8>| t.len() > 0)
			.collect::<Vec<_>>();

		let mut probable_key_bytes = Vec::new();
		for t in transposed {
			let mut scored = (0..=255).map(|k| {
				let dec = xor_encode(&t, &[k]);
				let score = score_text(&bytes_to_string(&dec));
				(k, dec, score)
			}).collect::<Vec<_>>();
			scored.sort_by(|kts1, kts2| kts1.2.total_cmp(&kts2.2));
			probable_key_bytes.push(scored.pop().unwrap().0);
		}

		let probable_strings: Vec<String> = ciphertexts.iter()
			.map(|ct| bytes_to_safe_string(&xor_encode(&ct, &probable_key_bytes)))
			.collect();

		println!("Set 3 Challenge 19: {} / {} / {} / {}", probable_strings[0], probable_strings[1], probable_strings[2], probable_strings[3]);
	}
}
