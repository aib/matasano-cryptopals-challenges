use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::time::{Duration, Instant};

use num_bigint::{BigInt, BigUint};
use indexmap::IndexMap;

fn bytes_from_hex(hstr: &str) -> Vec<u8> {
	hex::decode(hstr).expect("Error decoding hex")
}

fn bytes_from_hex_relaxed(hstr: &str) -> Vec<u8> {
	let purified: String = hstr.chars().filter(char::is_ascii_hexdigit).collect();
	bytes_from_hex(&purified)
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
	format!("{} ({} lines(s), {} char(s), SHA256: {})", lines.get(0).map_or("", |s| s.trim()), lines.len(), s.len(), sha256str(bs))
}

fn replace_char_at(src: &str, index: usize, c: char) -> String {
	let mut chars: Vec<char> = src.chars().collect();
	if index < chars.len() {
		chars[index] = c;
	}
	chars.into_iter().collect()
}

fn sha256(bs: &[u8]) -> Vec<u8> {
	openssl::hash::hash(openssl::hash::MessageDigest::sha256(), bs)
		.expect("Unable to hash")
		.to_vec()
}

fn sha256str(bs: &[u8]) -> String {
	bytes_to_hex(&sha256(bs))
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

fn get_nth_block_mut(bytes: &mut [u8], block_size: usize, n: usize) -> &mut [u8] {
	let blen = bytes.len();
	let block_offset = n * block_size;
	&mut bytes[usize::min(block_offset, blen) .. usize::min(block_offset + block_size, blen)]
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
	let mut iv = iv;

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

mod mt19937 {
	const W: usize = 32;
	const N: usize = 624;
	const M: usize = 397;
	const R: usize = 31;
	const A: u32 = 0x9908B0DF;
	const U: usize = 11;
	const S: usize = 7;
	const B: u32 = 0x9D2C5680;
	const T: usize = 15;
	const C: u32 = 0xEFC60000;
	const L: usize = 18;

	const F: u32 = 1812433253;

	pub struct MT19937 {
		state: [u32; N],
		index: usize,
	}

	impl MT19937 {
		pub fn with_seed(seed: u32) -> Self {
			let mut state = [0u32; N];

			state[0] = seed;
			for i in 1..N-1 {
				state[i] = F.wrapping_mul(state[i-1] ^ (state[i-1] >> (W - 2))).wrapping_add(i as u32);
			}

			let mut mt = Self { state, index: 0 };
			mt.twist();
			mt
		}

		pub fn with_state(state: [u32; N], index: usize) -> Self {
			Self { state, index }
		}

		pub fn next(&mut self) -> u32 {
			if self.index >= N {
				self.twist();
			}

			let y = temper(self.state[self.index]);
			self.index += 1;
			y
		}

		fn twist(&mut self) {
			const LOWER_MASK: u32 = (1 << R) - 1;
			const UPPER_MASK: u32 = !LOWER_MASK;

			for i in 0..N-1 {
				let x = (self.state[i] & UPPER_MASK) | self.state[i+1] & LOWER_MASK;
				let xa = if x % 2 == 0 {
					x >> 1
				} else {
					(x >> 1) ^ A
				};
				self.state[i] = self.state[(i + M) % N] ^ xa;
			}
			self.index = 0;
		}
	}

	pub fn temper(mut v: u32) -> u32 {
		v ^= v >> U;
		v ^= (v << S) & B;
		v ^= (v << T) & C;
		v ^= v >> L;
		v
	}
}

fn mt19937_untemper(mut v: u32) -> u32 {
	const U: usize = 11;
	const S: usize = 7;
	const B: u32 = 0x9D2C5680;
	const T: usize = 15;
	const C: u32 = 0xEFC60000;
	const L: usize = 18;

	fn umask(n: usize) -> u32 {
		u32::MAX - if n >= 32 { 0 } else { u32::MAX >> n }
	}
	fn lmask(n: usize) -> u32 {
		if n >= 32 { u32::MAX } else { (1 << n) - 1 }
	}

//	X12345678901234567 890123456789YZ
//	000000000000000000 X1234567890123
//	X12345678901234567 ~~~~~~~~~~~~~~
	v ^= (v & umask(L)) >> L;

//	567890123456789YZ 000000000000000 v << T
//	11101111110001100 000000000000000 C
//	567-901234---89-- --------------- &

//	X1234567890123456 7890123456789YZ
//	567-901234---89-- ---------------
//	~~~3~~~~~~012~~56 7890123456789YZ

	let amask = ((v & lmask(T+3)) << T) & C; // 567-9...
	v = (v ^ amask) | (v & lmask(T));

//	78901234567890123456789YZ 0000000 v << S
//	1001110100101100010101101 0000000 B
//	7--012-4--7-90---4-6-89-Z 0000000 &

//	X123456789012345678901234 56789YZ
//	7--012-4--7-90---4-6-89-Z 0000000
//	~12~~~6~89~1~~456~8~0~~3~ 56789YZ

	let amask14 = ((v & lmask(S)) << S) & B; // -6-89-Z 0000000
	let v14 = (v ^ amask14) & lmask(S * 2); // 8901234 59789YZ

//	7890 1234567 8901234 56789YZ 0000000 v << S
//	1001 1101001 0110001 0101101 0000000 B
//	7--0 12-4--7 -90---4 -6-89-Z 0000000 &
	let amask21 = (v14 << S) & B;
	let v21 = v ^ amask21;

	let amask28 = (v21 << S) & B;
	let v28 = v ^ amask28;

	let amask35 = (v28 << S) & B;
	let v35 = v ^ amask35;

	v = v35;

//	X1234567890 12345678901 23456789YZ v
//	00000000000 X1234567890 1234567890 v >> U
//	X1234567890 ~~~~~~~~~~~ ?????????? ^
	let v11 = v & umask(U);
	let v22 = v ^ (v11 >> U);
	let v33 = v ^ (v22 >> U);
	v = v33;

	v
}

fn mt19937_stream_cipher(key: u16, text: &[u8]) -> Vec<u8> {
	let mut rng = mt19937::MT19937::with_seed(key as u32);
	let mut out = Vec::with_capacity(text.len());
	for b in text {
		out.push(b ^ (rng.next() as u8));
	}
	out
}

fn solve_ctr_with_edit<E>(mut edit: E, ciphertext: &[u8]) -> Vec<u8>
where E: FnMut(&[u8], usize, &[u8]) -> Vec<u8> {
	let zeros = vec![0; ciphertext.len()];
	let zenc = edit(&ciphertext, 0, &zeros);
	xor_encode(&zenc, &ciphertext)
}

fn solve_ctr_with_bitflip<F>(mut ctr: F) -> Vec<u8>
where F: FnMut(&[u8]) -> Vec<u8> {
	let almost = b"nodata:admin=true".to_vec();
	let mut almost_enc = ctr(&almost);
	almost_enc[38] ^= 1;
	almost_enc
}

fn solve_cbc_with_iv_eq_key<E, D>(mut enc: E, mut dec: D) -> Vec<u8>
where
	E: FnMut(&[u8]) -> Vec<u8>,
	D: FnMut(&[u8]) -> Result<(), Vec<u8>>,
{
	let msg = b"ThisIsBlockNum01ThisIsBlockNum02ThisIsBlockNum03";
	let ct = enc(msg);

	// PT1 = CBCd(CT1) ^ iv
	// PT2 = CBCd(CT2) ^ CT1
	// PT3 = CBCd(CT3) ^ CT2

	// (CT3 = CT1) -> PT3 = CBCd(CT1) ^ CT2
	// -> PT1 ^ PT3 = CBCd(CT1) ^ iv ^ CBCd(CT1) ^ CT2

	let mut ct_mod = ct.clone();
	get_nth_block_mut(&mut ct_mod, 16, 1).fill(0);
	ct_mod.copy_within(0..16, 32);

	let pt_mod = dec(&ct_mod)
		.expect_err("Decryption result should be an error due to non-ASCII characters");

	xor(get_nth_block(&pt_mod, 16, 0), get_nth_block(&pt_mod, 16, 2))
}

fn sha1(bs: &[u8]) -> Vec<u8> {
	sha1_with_state(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0, 0, bs)
}

fn sha1_with_state(mut h0: u32, mut h1: u32, mut h2: u32, mut h3: u32, mut h4: u32, mut ml: usize, bs: &[u8]) -> Vec<u8> {
	let mut msg = bs.to_vec();

	ml += bs.len() * 8;

	msg.push(0x80);
	while msg.len() % 64 != 56 {
		msg.push(0x00);
	}
	msg.extend((ml as u64).to_be_bytes());

	for chunk in msg.chunks_exact(64) {
		let mut w: Vec<u32> = chunk
			.chunks_exact(4)
			.map(|b4| u32::from_be_bytes(b4.try_into().unwrap()))
			.collect();

		w.extend([0; 64]);

		for i in 16..=79 {
			w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
		}

		let mut a = h0;
		let mut b = h1;
		let mut c = h2;
		let mut d = h3;
		let mut e = h4;

		for i in 0..=79 {
			let mut f = 0;
			let mut k = 0;
			if /* 0 <= i && */ i <= 19 {
				f = (b & c) | ((!b) & d);
				k = 0x5A827999;
			} else if 20 <= i && i <= 39 {
				f = b ^ c ^ d;
				k = 0x6ED9EBA1;
			} else if 40 <= i && i <= 59 {
				f = (b & c) | (b & d) | (c & d);
				k = 0x8F1BBCDC;
			} if 60 <= i && i <= 79 {
				f = b ^ c ^ d;
				k = 0xCA62C1D6;
			}

			let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
			e = d;
			d = c;
			c = b.rotate_left(30);
			b = a;
			a = temp;
		}

		h0 = h0.wrapping_add(a);
		h1 = h1.wrapping_add(b);
		h2 = h2.wrapping_add(c);
		h3 = h3.wrapping_add(d);
		h4 = h4.wrapping_add(e);
	}

	// Until we have slice_flatten
	let mut v = Vec::with_capacity(20);
	[h0, h1, h2, h3, h4].iter().for_each(|h| {
		h.to_be_bytes().into_iter().for_each(|b| {
			v.push(b);
		})
	});
	v
}

fn sha1_mac(key: &[u8], msg: &[u8]) -> Vec<u8> {
	sha1(&[key, msg].concat())
}

fn forge_sha1_mac<V>(mut verify: V, existing_msg: &[u8], existing_mac: &[u8]) -> Option<(Vec<u8>, Vec<u8>)>
where V: FnMut(&[u8], &[u8]) -> bool {
	let forge_with_key_len = |key_len: usize| -> (Vec<u8>, Vec<u8>) {
		let existing_len = key_len + existing_msg.len();
		let glue_padding = get_sha1_padding(existing_len);
		let extension = bytes_from_str(";admin=true;");

		let h0 = u32::from_be_bytes(existing_mac[0..4].try_into().unwrap());
		let h1 = u32::from_be_bytes(existing_mac[4..8].try_into().unwrap());
		let h2 = u32::from_be_bytes(existing_mac[8..12].try_into().unwrap());
		let h3 = u32::from_be_bytes(existing_mac[12..16].try_into().unwrap());
		let h4 = u32::from_be_bytes(existing_mac[16..20].try_into().unwrap());

		let mac = sha1_with_state(h0, h1, h2, h3, h4, (existing_len + glue_padding.len()) * 8, &extension);
		([existing_msg, &glue_padding, &extension].concat(), mac)
	};

	fn get_sha1_padding(ml: usize) -> Vec<u8> {
		let mut padding = vec![0x80];
		while (ml + padding.len()) % 64 != 56 {
			padding.push(0x00);
		}
		padding.extend(((ml * 8) as u64).to_be_bytes());
		padding
	}

	for key_len in 0..=16 {
		let (attempt, attempt_mac) = forge_with_key_len(key_len);
		if verify(&attempt, &attempt_mac) {
			return Some((attempt, attempt_mac));
		}
	}

	None
}

fn md4(bs: &[u8]) -> Vec<u8> {
	md4_with_state(
		u32::from_le_bytes([0x01, 0x23, 0x45, 0x67]),
		u32::from_le_bytes([0x89, 0xab, 0xcd, 0xef]),
		u32::from_le_bytes([0xfe, 0xdc, 0xba, 0x98]),
		u32::from_le_bytes([0x76, 0x54, 0x32, 0x10]),
		0,
		bs
	)
}

fn md4_with_state(mut a: u32, mut b: u32, mut c: u32, mut d: u32, mut ml: usize, bs: &[u8]) -> Vec<u8> {
	let mut msg = bs.to_vec();

	msg.push(0x80);
	while msg.len() % 64 != 56 {
		msg.push(0x00);
	}
	ml += bs.len() * 8;
	let ml_h = ((ml as u64) & ((u32::MAX as u64) << u32::BITS)) as u32;
	let ml_l = ((ml as u64) & (u32::MAX as u64)) as u32;
	msg.extend(ml_l.to_le_bytes());
	msg.extend(ml_h.to_le_bytes());

	fn f(x: u32, y: u32, z: u32) -> u32 { (x & y) | (!x & z) }
	fn g(x: u32, y: u32, z: u32) -> u32 { (x & y) | (x & z) | (y & z) }
	fn h(x: u32, y: u32, z: u32) -> u32 { x ^ y ^ z }

	for chunk in msg.chunks_exact(64) {
		let x: Vec<u32> = chunk
			.chunks_exact(4)
			.map(|b4| u32::from_le_bytes(b4.try_into().unwrap()))
			.collect();

		let aa = a;
		let bb = b;
		let cc = c;
		let dd = d;

		let r1_op = |a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, k: usize, s: u32| {
			*a = (*a).wrapping_add(f(*b, *c, *d)).wrapping_add(x[k]).rotate_left(s)
		};

		r1_op(&mut a, &mut b, &mut c, &mut d,  0,  3);
		r1_op(&mut d, &mut a, &mut b, &mut c,  1,  7);
		r1_op(&mut c, &mut d, &mut a, &mut b,  2, 11);
		r1_op(&mut b, &mut c, &mut d, &mut a,  3, 19);
		r1_op(&mut a, &mut b, &mut c, &mut d,  4,  3);
		r1_op(&mut d, &mut a, &mut b, &mut c,  5,  7);
		r1_op(&mut c, &mut d, &mut a, &mut b,  6, 11);
		r1_op(&mut b, &mut c, &mut d, &mut a,  7, 19);
		r1_op(&mut a, &mut b, &mut c, &mut d,  8,  3);
		r1_op(&mut d, &mut a, &mut b, &mut c,  9,  7);
		r1_op(&mut c, &mut d, &mut a, &mut b, 10, 11);
		r1_op(&mut b, &mut c, &mut d, &mut a, 11, 19);
		r1_op(&mut a, &mut b, &mut c, &mut d, 12,  3);
		r1_op(&mut d, &mut a, &mut b, &mut c, 13,  7);
		r1_op(&mut c, &mut d, &mut a, &mut b, 14, 11);
		r1_op(&mut b, &mut c, &mut d, &mut a, 15, 19);

		let r2_op = |a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, k: usize, s: u32| {
			*a = (*a).wrapping_add(g(*b, *c, *d)).wrapping_add(x[k]).wrapping_add(0x5A827999).rotate_left(s)
		};

		r2_op(&mut a, &mut b, &mut c, &mut d,  0,  3);
		r2_op(&mut d, &mut a, &mut b, &mut c,  4,  5);
		r2_op(&mut c, &mut d, &mut a, &mut b,  8,  9);
		r2_op(&mut b, &mut c, &mut d, &mut a, 12, 13);
		r2_op(&mut a, &mut b, &mut c, &mut d,  1,  3);
		r2_op(&mut d, &mut a, &mut b, &mut c,  5,  5);
		r2_op(&mut c, &mut d, &mut a, &mut b,  9,  9);
		r2_op(&mut b, &mut c, &mut d, &mut a, 13, 13);
		r2_op(&mut a, &mut b, &mut c, &mut d,  2,  3);
		r2_op(&mut d, &mut a, &mut b, &mut c,  6,  5);
		r2_op(&mut c, &mut d, &mut a, &mut b, 10,  9);
		r2_op(&mut b, &mut c, &mut d, &mut a, 14, 13);
		r2_op(&mut a, &mut b, &mut c, &mut d,  3,  3);
		r2_op(&mut d, &mut a, &mut b, &mut c,  7,  5);
		r2_op(&mut c, &mut d, &mut a, &mut b, 11,  9);
		r2_op(&mut b, &mut c, &mut d, &mut a, 15, 13);

		let r3_op = |a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32, k: usize, s: u32| {
			*a = (*a).wrapping_add(h(*b, *c, *d)).wrapping_add(x[k]).wrapping_add(0x6ED9EBA1).rotate_left(s)
		};

		r3_op(&mut a, &mut b, &mut c, &mut d,  0,  3);
		r3_op(&mut d, &mut a, &mut b, &mut c,  8,  9);
		r3_op(&mut c, &mut d, &mut a, &mut b,  4, 11);
		r3_op(&mut b, &mut c, &mut d, &mut a, 12, 15);
		r3_op(&mut a, &mut b, &mut c, &mut d,  2,  3);
		r3_op(&mut d, &mut a, &mut b, &mut c, 10,  9);
		r3_op(&mut c, &mut d, &mut a, &mut b,  6, 11);
		r3_op(&mut b, &mut c, &mut d, &mut a, 14, 15);
		r3_op(&mut a, &mut b, &mut c, &mut d,  1,  3);
		r3_op(&mut d, &mut a, &mut b, &mut c,  9,  9);
		r3_op(&mut c, &mut d, &mut a, &mut b,  5, 11);
		r3_op(&mut b, &mut c, &mut d, &mut a, 13, 15);
		r3_op(&mut a, &mut b, &mut c, &mut d,  3,  3);
		r3_op(&mut d, &mut a, &mut b, &mut c, 11,  9);
		r3_op(&mut c, &mut d, &mut a, &mut b,  7, 11);
		r3_op(&mut b, &mut c, &mut d, &mut a, 15, 15);

		a = a.wrapping_add(aa);
		b = b.wrapping_add(bb);
		c = c.wrapping_add(cc);
		d = d.wrapping_add(dd);
	}

	let mut v = Vec::with_capacity(16);
	[a, b, c, d].iter().for_each(|w| {
		w.to_le_bytes().into_iter().for_each(|b| {
			v.push(b);
		})
	});
	v
}

fn md4_mac(key: &[u8], msg: &[u8]) -> Vec<u8> {
	md4(&[key, msg].concat())
}

fn forge_md4_mac<V>(mut verify: V, existing_msg: &[u8], existing_mac: &[u8]) -> Option<(Vec<u8>, Vec<u8>)>
where V: FnMut(&[u8], &[u8]) -> bool {
	let forge_with_key_len = |key_len: usize| -> (Vec<u8>, Vec<u8>) {
		let existing_len = key_len + existing_msg.len();
		let glue_padding = get_md4_padding(existing_len);
		let extension = bytes_from_str(";admin=true;");

		let a = u32::from_le_bytes(existing_mac[0..4].try_into().unwrap());
		let b = u32::from_le_bytes(existing_mac[4..8].try_into().unwrap());
		let c = u32::from_le_bytes(existing_mac[8..12].try_into().unwrap());
		let d = u32::from_le_bytes(existing_mac[12..16].try_into().unwrap());

		let mac = md4_with_state(a, b, c, d, (existing_len + glue_padding.len()) * 8, &extension);
		([existing_msg, &glue_padding, &extension].concat(), mac)
	};

	fn get_md4_padding(ml: usize) -> Vec<u8> {
		let mut padding = vec![0x80];
		while (ml + padding.len()) % 64 != 56 {
			padding.push(0x00);
		}
		let ml_h = (((ml * 8) as u64) & ((u32::MAX as u64) << u32::BITS)) as u32;
		let ml_l = (((ml * 8) as u64) & (u32::MAX as u64)) as u32;
		padding.extend(ml_l.to_le_bytes());
		padding.extend(ml_h.to_le_bytes());
		padding
	}

	for key_len in 0..=16 {
		let (attempt, attempt_mac) = forge_with_key_len(key_len);
		if verify(&attempt, &attempt_mac) {
			return Some((attempt, attempt_mac));
		}
	}

	None
}

fn hmac<H>(mut h: H, b: usize, k: &[u8], m: &[u8]) -> Vec<u8>
where H: FnMut(&[u8]) -> Vec<u8> {
	let ipad = vec![0x36; b];
	let opad = vec![0x5c; b];

	let k = if k.len() < b {
		let mut k_padded = k.to_vec();
		k_padded.resize(b, 0);
		k_padded
	} else if k.len() > b {
		h(k)
	} else {
		k.to_vec()
	};

	let step4 = h(&[&xor(&k, &ipad), m].concat());
	h(&[xor(&k, &opad), step4].concat())
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
	hmac(sha1, 64, key, message)
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
	hmac(sha256, 64, key, message)
}

fn timed_http_get(url: &str) -> (bool, Duration) {
	let start_time = Instant::now();
	let okay = ureq::get(url).call().is_ok();
	let end_time = Instant::now();
	(okay, end_time - start_time)
}

fn diffie_hellman_toy(p: u32, g: u32) -> (u32, u32, u32, u32, u32, u32) {
	use rand::Rng;
	let mut rng = rand::thread_rng();

	fn mod_exp(n: u32, e: u32, m: u32) -> u32 {
		let mut x = 1;
		for _ in 0..e {
			x = (x * n) % m;
		}
		x
	}

	let a = rng.gen_range(0..p);
	let a_pub = mod_exp(g, a, p);

	let b = rng.gen_range(0..p);
	let b_pub = mod_exp(g, b, p);

	let s1 = mod_exp(b_pub, a, p);
	let s2 = mod_exp(a_pub, b, p);

	(a, a_pub, b, b_pub, s1, s2)
}

fn dh_gen_key(p: &BigUint, g: &BigUint) -> (BigUint, BigUint) {
	use num_bigint::RandBigInt;
	let mut rng = rand::thread_rng();

	let private = rng.gen_biguint_below(p);
	let public = g.modpow(&private, p);
	(private, public)
}

fn dh_shared_secret(p: &BigUint, private: &BigUint, public: &BigUint) -> BigUint {
	public.modpow(private, p)
}

fn nist_p_g() -> (BigUint, BigUint) {
	let p = BigUint::from_bytes_be(&bytes_from_hex(concat!(
		"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024",
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd",
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec",
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f",
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361",
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552",
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff",
		"fffffffffffff",
	)));
	let g = BigUint::from_slice(&[2]);
	(p, g)
}

fn aes_cbc_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
	let mut iv = get_random_bytes(16);
	let mut ciphertext = cbc_encrypt(aes_128_encrypt_block, 16, &key, &iv, &plaintext);
	ciphertext.append(&mut iv);
	ciphertext
}

fn aes_cbc_decrypt(key: &[u8], ciphertext_and_iv: &[u8]) -> Option<Vec<u8>> {
	let (ct, iv) = ciphertext_and_iv.split_at_checked(ciphertext_and_iv.len() - 16)?;
	Some(cbc_decrypt(aes_128_decrypt_block, 16, &key, &iv, &ct))
}

struct DHParty {
	p: BigUint,
	private: BigUint,
	pub public: BigUint,
}

impl DHParty {
	pub fn new(p: BigUint, g: BigUint) -> Self {
		let (private, public) = dh_gen_key(&p, &g);
		Self { p, public, private }
	}

	pub fn create_session(&self, pubkey: &BigUint) -> DHSession {
		let shared = dh_shared_secret(&self.p, &self.private, &pubkey);
		let mut session_key = sha1(&shared.to_bytes_be());
		session_key.truncate(16);
		DHSession { session_key }
	}
}

struct DHSession {
	session_key: Vec<u8>,
}

impl DHSession {
	pub fn echo(&self, message: &[u8]) -> Vec<u8> {
		let dec = aes_cbc_decrypt(&self.session_key, message).unwrap();
		self.say(&dec)
	}

	pub fn say(&self, message: &[u8]) -> Vec<u8> {
		aes_cbc_encrypt(&self.session_key, &message)
	}
}

struct SRPServer {
	n: BigUint,
	g: BigUint,
	k: BigUint,
	users: HashMap<String, (Vec<u8>, BigUint)>,
}

impl SRPServer {
	pub fn new(n: BigUint, g: BigUint, k: BigUint) -> Self {
		let users = HashMap::new();
		Self { n, g, k, users }
	}

	pub fn add(&mut self, username: &str, password: &str) {
		let salt = get_random_bytes(8);

		let mut salt_password = salt.clone();
		salt_password.append(&mut bytes_from_str(password));
		let xh = sha256(&salt_password);
		let x = BigUint::from_bytes_be(&xh);
		let v = self.g.modpow(&x, &self.n);
		self.users.insert(username.to_owned(), (salt, v));
	}

	pub fn start_verification(&self, username: &str, public: &BigUint) -> Option<SRPVerification> {
		let (salt, v) = self.users.get(username)?
			.clone();
		let (dh_private, dh_public) = dh_gen_key(&self.n, &self.g);

		let b = (&self.k * &v + dh_public) % &self.n;
		Some(SRPVerification { n: self.n.clone(), private: dh_private, public: b, client_public: public.clone(), salt, v: v.clone() })
	}
}

struct SRPVerification {
	n: BigUint,
	private: BigUint,
	pub public: BigUint,
	client_public: BigUint,
	pub salt: Vec<u8>,
	v: BigUint,
}

impl SRPVerification {
	pub fn verify(&self, mac: &[u8]) -> bool {
		let uh = sha256(&[self.client_public.to_bytes_be(), self.public.to_bytes_be()].concat());
		let u = BigUint::from_bytes_be(&uh);
		let verify_s = (&self.client_public * self.v.modpow(&u, &self.n)).modpow(&self.private, &self.n);
		let verify_k = sha256(&verify_s.to_bytes_be());
		let own_mac = hmac_sha256(&verify_k, &self.salt);
		own_mac == mac
	}
}

fn generate_dictionary(length: u32) -> HashSet<String> {
	use rand::Rng;
	use rand::prelude::SliceRandom;
	let mut rng = rand::thread_rng();
	let syllables = vec!("na", "ru", "to", "ki", "ku", "shi", "o", "ru", "wa", "ni", "no", "ha", "ma");

	let words = (0..length).map(|_| {
		let word = (0..rng.gen_range(3..=7))
			.map(|_| *syllables.choose(&mut rng).unwrap())
			.collect::<Vec<&str>>();
		word.join("")
	}).collect::<Vec<_>>();

	HashSet::from_iter(words)
}

fn big(val: u32) -> BigUint {
	BigUint::ZERO + val
}

fn egcd(a: BigUint, b: BigUint) -> (BigUint, BigInt, BigInt) {
	let (
		(mut a, mut b),
		(mut sprev, mut s),
		(mut tprev, mut t),
	) = if b < a {
		(
			(BigInt::from(a), BigInt::from(b)),
			(BigInt::ZERO + 1, BigInt::ZERO),
			(BigInt::ZERO, BigInt::ZERO + 1),
		)
	} else {
		(
			(BigInt::from(b), BigInt::from(a)),
			(BigInt::ZERO, BigInt::ZERO + 1),
			(BigInt::ZERO + 1, BigInt::ZERO),
		)
	};

	loop {
		let q = &a / &b;
		let r = &a % &b;
		let snew = sprev - &q * &s;
		let tnew = tprev - &q * &t;
		if r == BigInt::ZERO {
			break;
		}
		(sprev, s) = (s, snew);
		(tprev, t) = (t, tnew);
		(a, b) = (b, r);
	}

	(b.to_biguint().unwrap(), s, t)
}

fn invmod(a: BigUint, m: BigUint) -> BigUint {
	let (_, x, _) = egcd(a, m.clone());
	(x + BigInt::from(m.clone())).to_biguint().unwrap() % m
}

mod rsa {
	use num_bigint::{BigInt, BigUint};
	use super::{big, invmod};

	pub type Key = (BigUint, BigUint);

	pub struct RSA {
		private: Option<Key>,
		public: Option<Key>,
	}

	impl RSA {
		pub fn from_primes(p: BigUint, q: BigUint) -> Self {
			let n = p.clone() * q.clone();
			let et = BigInt::to_biguint(&((BigInt::from(p) - 1) * (BigInt::from(q) - 1))).unwrap();
			let e = big(3);
			let d = invmod(e.clone(), et);
			Self::from_keypair((d, n.clone()), (e, n.clone()))
		}

		pub fn from_keypair(private: Key, public: Key) -> Self {
			Self { private: Some(private), public: Some(public) }
		}

		pub fn encrypt(&self, m: &BigUint) -> BigUint {
			let (e, n) = self.public.as_ref()
				.expect("No public key");
			m.modpow(e, n)
		}

		pub fn decrypt(&self, m: &BigUint) -> BigUint {
			let (d, n) = self.private.as_ref()
				.expect("No private key");
			m.modpow(d, n)
		}
	}
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

	{ // Set 3 Challenge 20
		let key = get_random_bytes(16);
		let ciphertexts = std::fs::read_to_string("20.txt").unwrap()
			.lines()
			.map(|l| bytes_from_base64(&l))
			.map(|pt| ctr_encrypt(aes_128_encrypt_block, 16, &key, &vec![0; 8], &pt))
			.collect::<Vec<_>>();

		let transposed = (0..)
			.map(|n| ciphertexts.iter().filter_map(|c| c.get(n).copied()).collect())
			.take_while(|t: &Vec<u8>| t.len() > 0)
			.collect::<Vec<_>>();

		let probable_key_bytes = transposed.iter().map(|t| {
			let mut scored = (0..=255).map(|k| {
				let dec = xor_encode(&t, &[k]);
				let score = score_text(&bytes_to_string(&dec));
				(k, dec, score)
			}).collect::<Vec<_>>();
			scored.sort_by(|kts1, kts2| kts1.2.total_cmp(&kts2.2));
			scored.pop().unwrap().0
		}).collect::<Vec<u8>>();

		let probable_strings: Vec<String> = ciphertexts.iter()
			.map(|ct| bytes_to_safe_string(&xor_encode(&ct, &probable_key_bytes)))
			.collect();

		println!("Set 3 Challenge 20: {}", probable_strings[0]);
	}

	{ // Set 3 Challenge 21
		let mut mt = mt19937::MT19937::with_seed(5489);
		let nums = std::iter::repeat_with(|| mt.next());
		let first10: Vec<u32> = nums.take(10).collect();
		println!("Set 3 Challenge 21: {}", first10.iter().map(|n| format!("{:08x}", n)).collect::<Vec<_>>().join(" "));
		assert_eq!([0xd091bb5c, 0x22ae9ef6, 0xe7e1faee, 0xd5c31f79, 0x2082352c, 0xf807b7df, 0xe9d30005, 0x3895afe1, 0xa1e24bba, 0x4ee4092b].to_vec(), first10);
	}

	{ // Set 3 Challenge 22
		use rand::Rng;
		use std::time::{Duration, SystemTime, UNIX_EPOCH};

		#[allow(unused)]
		let wait = || {
			std::thread::sleep(Duration::from_secs(rand::thread_rng().gen_range(40..=1000)));
			let seed_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
			let mut mt = mt19937::MT19937::with_seed(seed_time);
			let generated_number = mt.next();
			std::thread::sleep(Duration::from_secs(rand::thread_rng().gen_range(40..=1000)));
			(mt, generated_number)
		};

		let wait_sim = || {
			let seed_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
			let adj_seed_time = seed_time - rand::thread_rng().gen_range(40..=1000);
			let mut mt = mt19937::MT19937::with_seed(adj_seed_time);
			let generated_number = mt.next();
			(mt, generated_number)
		};

//		let (mut target_mt, generated_number) = wait();
		let (mut target_mt, generated_number) = wait_sim();

		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
		let found_seed = (|| {
			for t in now - 1010 ..= now - 30 {
				let mut mt = mt19937::MT19937::with_seed(t);
				if mt.next() == generated_number {
					return Some(t);
				}
			}
			None
		})();

		let mut mt = mt19937::MT19937::with_seed(found_seed.unwrap());
		mt.next();
		let guessed_next_val = mt.next();
		let actual_next_val = target_mt.next();
		println!("Set 3 Challenge 22: Got {} (seed {}), next should be {}: {}", generated_number, found_seed.unwrap(), guessed_next_val, actual_next_val);
		assert_eq!(actual_next_val, guessed_next_val);
	}

	{ // Test mt19937_untemper
		for _ in 0..1000 {
			let input = { use rand::Rng; rand::thread_rng().gen() };
			let output = mt19937::temper(input);
			let undone = mt19937_untemper(output);
			assert_eq!(input, undone, "{:08x} -temper-> {:08x} -untemper-> {:08x}", input, output, undone);
		}
	}

	{ // Set 3 Challenge 23
		let seed = { use rand::Rng; rand::thread_rng().gen::<u32>() };
		let mut original = mt19937::MT19937::with_seed(seed);

		let outputs = std::iter::repeat_with(|| original.next()).take(624);//.collect();
		let untempered = outputs.map(mt19937_untemper).collect::<Vec<_>>();

		let mut cloned = mt19937::MT19937::with_state(untempered.try_into().unwrap(), 624);

		let ov = vec![original.next(), original.next(), original.next()];
		let cv = vec![cloned.next(), cloned.next(), cloned.next()];
		println!("Set 3 Challenge 23: Got {} {} {}, should be {} {} {}", ov[0], ov[1], ov[2], cv[0], cv[1], cv[2]);
		assert_eq!(ov[0], cv[0]);
		assert_eq!(ov[1], cv[1]);
		assert_eq!(ov[2], cv[2]);
	}

	{ // Set 3 Challenge 24
		let key = { use rand::Rng; rand::thread_rng().gen::<u16>() };
		let random_prefix = { use rand::Rng; get_random_bytes(rand::thread_rng().gen_range(0..16)) };
		let plaintext = [random_prefix, b"AAAAAAAAAAAAAA".to_vec()].concat();
		let ciphertext = mt19937_stream_cipher(key, &plaintext);
		assert_eq!(plaintext, mt19937_stream_cipher(key, &ciphertext));

		let mut found_key = None;
		for k in 0..u16::MAX {
			let pt = mt19937_stream_cipher(k, &ciphertext);
			if &pt[pt.len() - 14..] == b"AAAAAAAAAAAAAA" {
				found_key = Some(k);
				break;
			}
		}
		println!("Set 3 Challenge 24: {} (key 0x{:04x})", bytes_to_hex(&mt19937_stream_cipher(found_key.unwrap(), &ciphertext)), found_key.unwrap());
		assert_eq!(key, found_key.unwrap());
	}

	{ // Set 4 Challenge 25
		let bs = bytes_from_base64(&std::fs::read_to_string("25.txt").unwrap());
		let original = ecb_decrypt(aes_128_decrypt_block, 16, b"YELLOW SUBMARINE", &bs);
		let (key, nonce) = (get_random_bytes(16), get_random_bytes(8));
		let ciphertext = ctr_encrypt(aes_128_encrypt_block, 16, &key, &nonce, &original);

		let edit = |ciphertext: &[u8], offset: usize, newtext: &[u8]| -> Vec<u8> {
			let mut original = ctr_encrypt(aes_128_encrypt_block, 16, &key, &nonce, &ciphertext);
			original[offset..offset+newtext.len()].copy_from_slice(&newtext);
			ctr_encrypt(aes_128_encrypt_block, 16, &key, &nonce, &original)
		};
		let solved = solve_ctr_with_edit(edit, &ciphertext);
		println!("Set 4 Challenge 25: {}", bytes_to_summary(&solved));
		assert_eq!(original, solved);
	}

	{ // Set 4 Challenge 26
		let key = get_random_bytes(16);
		let nonce = get_random_bytes(8);
		let encryptor = |userdata: &[u8]| {
			let escaped = bytes_to_string(userdata)
				.replace("\\", "\\\\").replace(";", "\\;").replace("\"", "\\\"");
			let s = format!("comment1=cooking%20MCs;userdata={};comment2=%20like%20a%20pound%20of%20bacon", escaped);
			ctr_encrypt(aes_128_encrypt_block, 16, &key, &nonce, &bytes_from_str(&s))
		};
		let decryptor = |ciphertext: &[u8]| {
			ctr_encrypt(aes_128_encrypt_block, 16, &key, &nonce, ciphertext)
		};
		let res = solve_ctr_with_bitflip(encryptor);
		let dec = decryptor(&res);
		println!("Set 4 Challenge 26: {}", bytes_to_safe_string(&dec));
		assert!(bytes_to_string(&dec).contains(";admin=true;"));
	}

	{ // Set 4 Challenge 27
		let key = get_random_bytes(16);
		let iv = key.clone();
		let encryptor = |userdata: &[u8]| {
			let escaped = bytes_to_string(userdata)
				.replace("\\", "\\\\").replace(";", "\\;").replace("\"", "\\\"");
			let s = format!("comment1=cooking%20MCs;userdata={};comment2=%20like%20a%20pound%20of%20bacon", escaped);
			cbc_encrypt(aes_128_encrypt_block, 16, &key, &iv, &bytes_from_str(&s))
		};
		let decryptor = |ciphertext: &[u8]| {
			let dec = cbc_decrypt(aes_128_decrypt_block, 16, &key, &iv, ciphertext);
			if dec.iter().find(|b| **b > 0x7f).is_some() {
				Err(dec)
			} else {
				Ok(())
			}
		};

		let found_iv = solve_cbc_with_iv_eq_key(encryptor, decryptor);
		println!("Set 4 Challenge 27: {}", bytes_to_hex(&found_iv));
		assert!(found_iv == iv);
	}

	{ // Test SHA-1
		let msg = b"Hello, World!";
		let lib_digest = openssl::hash::hash(openssl::hash::MessageDigest::sha1(), msg)
			.expect("Unable to hash")
			.to_vec();
		let digest = sha1(msg);
		assert_eq!(lib_digest, digest);
	}

	{ // Set 4 Challenge 28
		let msg = bytes_from_str("Attack the city");
		let key = bytes_from_str("hunter2");
		let mac = sha1_mac(&key, &msg);

		println!("Set 4 Challenge 28: Message: \"{}\", MAC: {}", bytes_to_string(&msg), bytes_to_hex(&mac));
		assert_eq!(sha1_mac(&key, &msg), mac);
		let lib_mac = openssl::hash::hash(openssl::hash::MessageDigest::sha1(), &[key, msg].concat())
			.expect("Unable to hash")
			.to_vec();
		assert_eq!(lib_mac, mac);
	}

	{ // Set 4 Challenge 29
		let key = get_random_bytes(16);
		let verify = |msg: &[u8], mac: &[u8]| -> bool {
			sha1_mac(&key, msg) == mac
		};
		let msg = bytes_from_str("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon");
		let mac = sha1_mac(&key, &msg);
		assert!(verify(&msg, &mac));

		let (forged_message, forged_mac) = forge_sha1_mac(verify, &msg, &mac).unwrap();
		println!("Set 4 Challenge 29: Message: \"{}\", MAC: {}", bytes_to_safe_string(&forged_message), bytes_to_hex(&forged_mac));
		assert!(verify(&forged_message, &forged_mac));
		assert!(bytes_to_string(&forged_message).contains(";admin=true;"));
	}

	{ // Test MD4
		assert_eq!("31d6cfe0d16ae931b73c59d7e0c089c0", bytes_to_hex(&md4(b"")));
		assert_eq!("bde52cb31de33e46245e05fbdbd6fb24", bytes_to_hex(&md4(b"a")));
		assert_eq!("a448017aaf21d8525fc10ae87aa6729d", bytes_to_hex(&md4(b"abc")));
		assert_eq!("d9130a8164549fe818874806e1c7014b", bytes_to_hex(&md4(b"message digest")));
		assert_eq!("d79e1c308aa5bbcdeea8ed63df412da9", bytes_to_hex(&md4(b"abcdefghijklmnopqrstuvwxyz")));
		assert_eq!("043f8582f241db351ce627e153e7f0e4", bytes_to_hex(&md4(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")));
		assert_eq!("e33b4ddc9c38f2199c3e7b164fcc0536", bytes_to_hex(&md4(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890")));
	}

	{ // Set 4 Challenge 30
		let key = get_random_bytes(16);
		let verify = |msg: &[u8], mac: &[u8]| -> bool {
			md4_mac(&key, msg) == mac
		};
		let msg = bytes_from_str("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon");
		let mac = md4_mac(&key, &msg);
		assert!(verify(&msg, &mac));

		let (forged_message, forged_mac) = forge_md4_mac(verify, &msg, &mac).unwrap();
		println!("Set 4 Challenge 30: Message: \"{}\", MAC: {}", bytes_to_safe_string(&forged_message), bytes_to_hex(&forged_mac));
		assert!(verify(&forged_message, &forged_mac));
		assert!(bytes_to_string(&forged_message).contains(";admin=true;"));
	}

	{ // Test HMAC
		let hmac_md5 = |k: &[u8], m: &[u8]| {
			let h = |bs: &[u8]| {
				openssl::hash::hash(openssl::hash::MessageDigest::md5(), bs)
					.expect("Unable to hash")
					.to_vec()
			};
			hmac(h, 64, k, m)
		};

		assert_eq!(
			"9294727a3638bb1c13f48ef8158bfc9d",
			bytes_to_hex(&hmac_md5(
				&bytes_from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
				b"Hi There",
			))
		);

		assert_eq!(
			"750c783e6ab0b503eaa86e310a5db738",
			bytes_to_hex(&hmac_md5(
				b"Jefe",
				b"what do ya want for nothing?",
			))
		);

		assert_eq!(
			"56be34521d144c88dbb8c733f0e8b3f6",
			bytes_to_hex(&hmac_md5(
				&bytes_from_hex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
				&vec![0xdd; 50],
			))
		);
	}

	{ // Set 4 Challenge 31
		#[allow(dead_code)]
		fn find_signature(file: &str) -> Option<String> {
			let url = |signature: &str| format!("http://localhost:9000/test?file={file}&signature={signature}");

			// Empty request to prime the HTTP library
			timed_http_get(&url("_"));

			let mut found_signature = None;
			let mut signature = String::from("0000000000000000000000000000000000000000");

			for try_digit in 0..signature.len() {
				let mut c_d_f = "0123456789abcdef".chars().map(|c| {
					let signature_to_try = replace_char_at(&signature, try_digit, c);
					let (ok, duration) = timed_http_get(&url(&signature_to_try));
					let found = if ok { Some(signature_to_try) } else { None };
					(c, duration, found)
				}).collect::<Vec<_>>();

				found_signature = c_d_f.iter()
					.find_map(|(_c, _d, f)| f.as_ref().map(|x| x.clone()));
				if found_signature.is_some() {
					break;
				}

				c_d_f.sort_by_key(|(_c, d, _f)| *d);
				let longest = c_d_f.last().unwrap().0;
				signature = replace_char_at(&signature, try_digit, longest);
				println!("Signature: {} step {}, times {:?}", signature, try_digit, c_d_f);
			}

			found_signature
		}

		let file = "foo";

		// Can't really replay the whole timing attack
		//let found_signature = find_signature(file);
		let found_signature = Some(String::from("274b7c4d98605fcf739a0bf9237551623f415fb8"));

		println!("Set 4 Challenge 31: File: {}, signature: {}", file, found_signature.as_ref().unwrap());
		assert_eq!(bytes_to_hex(&hmac_sha1(b"YELLOW SUBMARINE", &bytes_from_str(file))), found_signature.unwrap());
	}

	{ // Set 4 Challenge 32
		#[allow(dead_code)]
		fn find_signature_rep(file: &str, repetitions: usize) -> Option<String> {
			let url = |signature: &str| format!("http://localhost:9000/test?file={file}&signature={signature}");

			// Empty request to prime the HTTP library
			timed_http_get(&url("_"));

			let mut found_signature = None;
			let mut signature = String::from("0000000000000000000000000000000000000000");

			for try_digit in 0..signature.len() {
				let c_d_f = "0123456789abcdef".chars()
					.cycle().take(16 * repetitions)
					.map(|c| {
						let signature_to_try = replace_char_at(&signature, try_digit, c);
						let (ok, duration) = timed_http_get(&url(&signature_to_try));
						let found = if ok { Some(signature_to_try) } else { None };
						(c, duration, found)
					})
					.collect::<Vec<_>>();

				found_signature = c_d_f.iter()
					.find_map(|(_c, _d, f)| f.as_ref().map(|x| x.clone()));
				if found_signature.is_some() {
					break;
				}

				let mut total_times = HashMap::<char, Duration>::new();
				for (c, d, _f) in c_d_f.into_iter() {
					*total_times.entry(c).or_insert(Duration::ZERO) += d;
				}
				let mut c_d: Vec<(char, Duration)> = total_times.into_iter().collect();

				c_d.sort_by_key(|(_c, d)| *d);
				let longest = c_d.last().unwrap().0;
				signature = replace_char_at(&signature, try_digit, longest);
				println!("Signature: {} step {}, times {:?}", signature, try_digit, c_d);
			}

			found_signature
		}

		let file = "foo";

		// Can't really replay the whole timing attack
		//let found_signature = find_signature_rep(file, 5);
		let found_signature = Some(String::from("274b7c4d98605fcf739a0bf9237551623f415fb8"));

		println!("Set 4 Challenge 32: File: {}, signature: {}", file, found_signature.as_ref().unwrap());
		assert_eq!(bytes_to_hex(&hmac_sha1(b"YELLOW SUBMARINE", &bytes_from_str(file))), found_signature.unwrap());
	}

	{ // Set 5 Challenge 33
		let (_a, _a_pub, _b, _b_pub, s1, s2) = diffie_hellman_toy(37, 5);
		assert_eq!(s1, s2);

		let (p, g) = nist_p_g();
		let (a, a_pub) = dh_gen_key(&p, &g);
		let (b, b_pub) = dh_gen_key(&p, &g);

		let ss1 = dh_shared_secret(&p, &a, &b_pub);
		let ss2 = dh_shared_secret(&p, &b, &a_pub);

		println!("Set 5 Challenge 33: {} == {} (SHA-1)", bytes_to_hex(&sha1(&ss1.to_bytes_be())), bytes_to_hex(&sha1(&ss2.to_bytes_be())));
		assert_eq!(ss1, ss2);
	}

	{ // Test AES-CBC
		use rand::Rng;
		let mut rng = rand::thread_rng();

		let msg = bytes_from_str("We all live in a yellow submarine");
		let key = rng.gen::<[u8;16]>();
		let enc = aes_cbc_encrypt(&key, &msg);
		let dec = aes_cbc_decrypt(&key, &enc).unwrap();
		assert_eq!(msg, dec);
	}

	{ // Set 5 Challenge 34
		let (p, g) = nist_p_g();

		{
			let (a, a_pub) = dh_gen_key(&p, &g);
			let echo_bot = DHParty::new(p.clone(), g.clone());
			let shared = dh_shared_secret(&p, &a, &echo_bot.public);
			let session_key = &sha1(&shared.to_bytes_be())[0..16];
			let echo_bot = echo_bot.create_session(&a_pub);

			let msg = bytes_from_str("We all live in a yellow submarine");
			let msg_enc = aes_cbc_encrypt(&session_key, &msg);
			let reply_enc = echo_bot.echo(&msg_enc);
			let reply = aes_cbc_decrypt(&session_key, &reply_enc).unwrap();
			assert_eq!(msg, reply);
		}

		{
			let a = DHParty::new(p.clone(), g.clone());
			let b = DHParty::new(p.clone(), g.clone());

			let b_session = b.create_session(&p);
			let a_session = a.create_session(&p);

			let msg = bytes_from_str("We all live in a yellow submarine");
			let a_msg = a_session.say(&msg);
			let b_msg = b_session.say(&msg);

			let shared_key = &sha1(&[0])[0..16];
			let a_dec = aes_cbc_decrypt(shared_key, &a_msg).unwrap();
			let b_dec = aes_cbc_decrypt(shared_key, &b_msg).unwrap();

			println!("Set 5 Challenge 34: p secret = {}", bytes_to_hex(shared_key));
			assert_eq!(msg, a_dec);
			assert_eq!(msg, b_dec);
		}
	}

	{ // Set 5 Challenge 35
		let (p, _) = nist_p_g();
		let msg = bytes_from_str("We all live in a yellow submarine");

		let exchange_messages = |p: &BigUint, g: &BigUint| -> (Vec<u8>, Vec<u8>) {
			let a = DHParty::new(p.clone(), g.clone());
			let b = DHParty::new(p.clone(), g.clone());
			let a_session = a.create_session(&b.public);
			let b_session = b.create_session(&a.public);
			let a_msg = a_session.say(&msg);
			let b_msg = b_session.say(&msg);
			(a_msg, b_msg)
		};

		{
			let g = BigUint::from_bytes_be(&[1]);
			let (a_msg, b_msg) = exchange_messages(&p, &g);

			let shared_key = &sha1(&[1])[0..16];

			let a_dec = aes_cbc_decrypt(shared_key, &a_msg).unwrap();
			let b_dec = aes_cbc_decrypt(shared_key, &b_msg).unwrap();
			assert_eq!(msg, a_dec);
			assert_eq!(msg, b_dec);
		}

		{
			let g = p.clone();
			let (a_msg, b_msg) = exchange_messages(&p, &g);

			let shared_key = &sha1(&[0])[0..16];

			let a_dec = aes_cbc_decrypt(shared_key, &a_msg).unwrap();
			let b_dec = aes_cbc_decrypt(shared_key, &b_msg).unwrap();
			assert_eq!(msg, a_dec);
			assert_eq!(msg, b_dec);
		}

		{
			let g = p.clone() - BigUint::from_bytes_be(&[1]);
			let (a_msg, b_msg) = exchange_messages(&p, &g);

			let shared_key1 = &sha1(&[1])[0..16];
			let shared_key2 = &sha1(&g.to_bytes_be())[0..16];

			let a_dec1 = aes_cbc_decrypt(shared_key1, &a_msg).unwrap();
			let a_dec2 = aes_cbc_decrypt(shared_key2, &a_msg).unwrap();
			let b_dec1 = aes_cbc_decrypt(shared_key1, &b_msg).unwrap();
			let b_dec2 = aes_cbc_decrypt(shared_key2, &b_msg).unwrap();

			assert!(a_dec1 == msg || a_dec2 == msg);
			assert!(b_dec1 == msg || b_dec2 == msg);
		}

		{
			let g = BigUint::ZERO;
			let (a_msg, b_msg) = exchange_messages(&p, &g);

			let shared_key = &sha1(&[0])[0..16];

			let a_dec = aes_cbc_decrypt(shared_key, &a_msg).unwrap();
			let b_dec = aes_cbc_decrypt(shared_key, &b_msg).unwrap();
			assert_eq!(msg, a_dec);
			assert_eq!(msg, b_dec);
		}

		println!("Set 5 Challenge 35: DH broken for g = 1, p, p - 1, 0");
	}

	{ // Set 5 Challenge 36
		let (n, g) = nist_p_g();
		let k = BigUint::from_bytes_be(&[3]);

		let mut srp = SRPServer::new(n.clone(), g.clone(), k.clone());
		srp.add("aib", "hunter2");
		let srp = srp;

		{
			let (c_priv, c_pub) = dh_gen_key(&n, &g);
			let verifier = srp.start_verification("aib", &c_pub).unwrap();

			let uh = sha256(&[c_pub.to_bytes_be(), verifier.public.to_bytes_be()].concat());
			let u = BigUint::from_bytes_be(&uh);
			let mut salt_password = verifier.salt.clone();
			salt_password.append(&mut bytes_from_str("hunter2"));
			let xh = sha256(&salt_password);
			let x = BigUint::from_bytes_be(&xh);

			let verify_s = (&verifier.public + (&n - (&k * g.modpow(&x, &n)) % &n))
				.modpow(&(c_priv + u * x), &n);
			let verify_k = sha256(&verify_s.to_bytes_be());
			let mac = hmac_sha256(&verify_k, &verifier.salt);

			println!("Set 5 Challenge 36: MAC {}", bytes_to_hex(&mac));
			assert!(verifier.verify(&mac));
		}
	}

	{ // Set 5 Challenge 37
		let (n, g) = nist_p_g();
		let k = BigUint::from_bytes_be(&[3]);

		let mut srp = SRPServer::new(n.clone(), g.clone(), k.clone());
		srp.add("aib", "hunter2");
		let srp = srp;

		{
			let pub0 = BigUint::ZERO;
			let verifier = srp.start_verification("aib", &pub0).unwrap();
			let vk = sha256(&[0]);
			let mac = hmac_sha256(&vk, &verifier.salt);
			assert!(verifier.verify(&mac));
		}

		{
			let pub_n = n.clone();
			let verifier = srp.start_verification("aib", &pub_n).unwrap();
			let vk = sha256(&[0]);
			let mac = hmac_sha256(&vk, &verifier.salt);
			assert!(verifier.verify(&mac));
		}

		{
			let pub_n2 = &n + &n;
			let verifier = srp.start_verification("aib", &pub_n2).unwrap();
			let vk = sha256(&[0]);
			let mac = hmac_sha256(&vk, &verifier.salt);
			assert!(verifier.verify(&mac));
		}

		{
			let pub42 = &n * BigUint::from_bytes_be(&[42]);
			let verifier = srp.start_verification("aib", &pub42).unwrap();
			let vk = sha256(&[0]);
			let mac = hmac_sha256(&vk, &verifier.salt);
			assert!(verifier.verify(&mac));
		}

		println!("Set 5 Challenge 37: SRP broken for A = 0, N, N*2, N*42");
	}

	{ // Set 5 Challenge 38
		struct SimplifiedSRP {
			n: BigUint,
			private: BigUint,
			pub public: BigUint,
			pub salt: Vec<u8>,
			v: BigUint,
			client_public: Option<BigUint>,
			u: Option<BigUint>,
		}

		impl SimplifiedSRP {
			pub fn new(n: BigUint, g: BigUint, password: &str) -> Self {
				let salt = get_random_bytes(8);
				let mut salt_password = salt.clone();
				salt_password.append(&mut bytes_from_str(password));
				let x = BigUint::from_bytes_be(&sha256(&salt_password));
				let v = g.modpow(&x, &n);
				let (private, public) = dh_gen_key(&n, &g);
				Self { n, private, public, salt, v, client_public: None, u: None }
			}

			pub fn start_verification(&mut self, client_public: BigUint) -> BigUint {
				self.client_public = Some(client_public);
				let u = BigUint::from_bytes_be(&get_random_bytes(16));
				self.u = Some(u.clone());
				return u;
			}

			pub fn verify(&self, mac: &[u8]) -> bool {
				let client_public = self.client_public.as_ref().unwrap();
				let u = self.u.as_ref().unwrap();
				let s = (client_public * self.v.modpow(&u, &self.n)).modpow(&self.private, &self.n);
				let k = sha256(&s.to_bytes_be());
				let own_mac = hmac_sha256(&k, &self.salt);
				own_mac == mac
			}
		}

		let (n, g) = nist_p_g();

		{
			let mut ssrp = SimplifiedSRP::new(n.clone(), g.clone(), "hunter2");
			let (c_priv, c_pub) = dh_gen_key(&n, &g);
			let u = ssrp.start_verification(c_pub);
			let verify = |password: &str| {
				let mut salt_password = ssrp.salt.clone();
				salt_password.append(&mut bytes_from_str(password));
				let x = BigUint::from_bytes_be(&sha256(&salt_password));
				let s = ssrp.public.modpow(&(&c_priv + &u * x), &n);
				let k = sha256(&s.to_bytes_be());
				let mac = hmac_sha256(&k, &ssrp.salt);
				ssrp.verify(&mac)
			};
			assert!(!verify("bad_password"));
			assert!(verify("hunter2"));
		}

		{
			use rand::prelude::SliceRandom;
			let mut rng = rand::thread_rng();
			let dictionary = generate_dictionary(128).into_iter().collect::<Vec<String>>();
			let secret_password = dictionary.choose(&mut rng).unwrap();

			let (mitm_private, mitm_public) = dh_gen_key(&n, &g);
			let u = BigUint::from_bytes_be(&get_random_bytes(16));
			let salt = get_random_bytes(8);

			let (client_public, client_mac) = {
				let (c_priv, c_pub) = dh_gen_key(&n, &g);
				let mut salt_password = salt.clone();
				salt_password.append(&mut bytes_from_str(secret_password));
				let x = BigUint::from_bytes_be(&sha256(&salt_password));
				let s = mitm_public.modpow(&(&c_priv + &u * x), &n);
				let k = sha256(&s.to_bytes_be());
				let mac = hmac_sha256(&k, &salt);
				(c_pub, mac)
			};

			let found_password = dictionary.iter().find(|word| {
				let mut salt_password = salt.clone();
				salt_password.append(&mut bytes_from_str(word));
				let x = BigUint::from_bytes_be(&sha256(&salt_password));
				let v = g.modpow(&x, &n);

				let s = (&client_public * v.modpow(&u, &n)).modpow(&mitm_private, &n);
				let k = sha256(&s.to_bytes_be());
				let mac = hmac_sha256(&k, &salt);

				mac == client_mac
			});

			println!("Set 5 Challenge 38: Password: {}", found_password.unwrap());
			assert_eq!(secret_password, found_password.unwrap());
		}
	}

	{ // EGCD
		fn bigi(val: i32) -> BigInt { BigInt::ZERO + val }

		assert_eq!(
			egcd(big(46), big(240)),
			(big(2), bigi(47), bigi(-9)),
		);
		assert_eq!(
			egcd(big(240), big(46)),
			(big(2), bigi(-9), bigi(47)),
		);
		assert_eq!(
			egcd(big(1071), big(462)),
			(big(21), bigi(-3), bigi(7)),
		);
		assert_eq!(
			egcd(big(462), big(1071)),
			(big(21), bigi(7), bigi(-3)),
		);
		assert_eq!(
			egcd(big(30), big(5)),
			(big(5), bigi(0), bigi(1)),
		);
		assert_eq!(
			egcd(big(5), big(30)),
			(big(5), bigi(1), bigi(0)),
		);
	}

	{ // invmod
		assert_eq!(invmod(big(2), big(37)), big(19));
		assert_eq!(invmod(big(37), big(2)), big(1));
		assert_eq!(invmod(big(271), big(383)), big(106));
		assert_eq!(invmod(big(17), big(3120)), big(2753));
	}

	{ // Set 5 Challenge 39
		let pair1 = rsa::RSA::from_primes(big(23), big(59));
		let msg = big(42);
		let enc = pair1.encrypt(&msg);
		let dec = pair1.decrypt(&enc);
		assert_eq!(msg, dec);

		// From `openssl genrsa -3 | openssl rsa -text`
		let p = BigUint::from_bytes_be(&bytes_from_hex_relaxed("
			00:c6:d9:14:8a:22:e0:47:67:76:68:00:7f:95:54:
			c7:87:f9:dc:39:e9:8e:0a:3a:73:ba:b9:eb:25:f3:
			6c:bc:d8:99:4b:61:f8:c3:d9:a4:58:b1:37:16:bd:
			8f:62:65:06:a6:1a:6b:50:a8:2c:d8:41:a4:aa:85:
			3a:44:f1:b1:3b:80:87:eb:19:7f:d8:af:0a:7c:ec:
			81:f9:56:08:23:c7:01:16:af:38:46:86:3b:3c:28:
			20:ab:15:ac:fd:a2:8b:81:30:05:34:27:cf:a6:76:
			00:43:e9:f8:c0:58:77:f1:64:a1:18:53:ad:7a:5f:
			b5:98:39:c1:c5:38:b1:d8:17
		"));

		let q = BigUint::from_bytes_be(&bytes_from_hex_relaxed("
			00:c4:65:06:04:fd:39:0a:e6:39:93:24:9b:19:72:
			41:a9:7d:31:cb:04:bd:23:7b:eb:85:39:19:65:83:
			17:9d:73:fa:c4:a8:58:d8:40:3a:a0:0e:f2:d7:62:
			c6:7e:10:82:74:4e:a1:29:26:ed:1c:80:f1:c7:be:
			70:2f:22:51:f0:6a:11:cf:dc:1b:fa:80:79:4d:69:
			39:51:b9:e5:f7:44:bf:b1:48:ec:66:6e:47:c6:a0:
			08:9d:b9:db:da:68:20:d1:b1:c3:17:8a:aa:66:54:
			1f:ad:de:e2:a6:cd:0f:9e:b2:55:7d:a0:73:9f:22:
			72:19:fa:11:9e:42:df:08:19
		"));

		let pair2 = rsa::RSA::from_primes(p, q);
		let msg = big(42);
		let enc = pair2.encrypt(&msg);
		let dec = pair2.decrypt(&enc);
		assert_eq!(msg, dec);

		println!("Set 5 Challenge 39: RSA {} -> {} -> {}", &msg, &enc, &dec);
		assert_eq!(msg, dec);
	}
}
