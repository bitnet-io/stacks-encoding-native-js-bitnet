use sha2::Digest;
use sha2::Sha256;
use std::convert::TryFrom;
use std::convert::TryInto;

const C32_CHARACTERS: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// C32 chars as an array, indexed by their ASCII code for O(1) lookups.
/// Supports lookups by uppercase and lowercase.
///
/// The table also encodes the special characters `O, L, I`:
///   * `O` and `o` as `0`
///   * `L` and `l` as `1`
///   * `I` and `i` as `1`
///
/// Table can be generated with:
/// ```
/// let mut table: [Option<u8>; 128] = [None; 128];
/// let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// for (i, x) in alphabet.as_bytes().iter().enumerate() {
///     table[*x as usize] = Some(i as u8);
/// }
/// let alphabet_lower = alphabet.to_lowercase();
/// for (i, x) in alphabet_lower.as_bytes().iter().enumerate() {
///     table[*x as usize] = Some(i as u8);
/// }
/// let specials = [('O', '0'), ('L', '1'), ('I', '1')];
/// for pair in specials {
///     let i = alphabet.find(|a| a == pair.1).unwrap() as isize;
///     table[pair.0 as usize] = Some(i as u8);
///     table[pair.0.to_ascii_lowercase() as usize] = Some(i as u8);
/// }
/// ```
const C32_CHARACTERS_MAP: [Option<u8>; 128] = [
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some(0),
    Some(1),
    Some(2),
    Some(3),
    Some(4),
    Some(5),
    Some(6),
    Some(7),
    Some(8),
    Some(9),
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some(10),
    Some(11),
    Some(12),
    Some(13),
    Some(14),
    Some(15),
    Some(16),
    Some(17),
    Some(1),
    Some(18),
    Some(19),
    Some(1),
    Some(20),
    Some(21),
    Some(0),
    Some(22),
    Some(23),
    Some(24),
    Some(25),
    Some(26),
    None,
    Some(27),
    Some(28),
    Some(29),
    Some(30),
    Some(31),
    None,
    None,
    None,
    None,
    None,
    None,
    Some(10),
    Some(11),
    Some(12),
    Some(13),
    Some(14),
    Some(15),
    Some(16),
    Some(17),
    Some(1),
    Some(18),
    Some(19),
    Some(1),
    Some(20),
    Some(21),
    Some(0),
    Some(22),
    Some(23),
    Some(24),
    Some(25),
    Some(26),
    None,
    Some(27),
    Some(28),
    Some(29),
    Some(30),
    Some(31),
    None,
    None,
    None,
    None,
    None,
];

#[allow(dead_code)]
fn c32_encode(input_bytes: &[u8]) -> String {
    let capacity = get_max_c32_encode_output_len(input_bytes.len());
    let mut buffer: Vec<u8> = vec![0; capacity];
    let bytes_written = c32_encode_to_buffer(input_bytes, &mut buffer).unwrap();
    buffer.truncate(bytes_written);
    String::from_utf8(buffer).unwrap()
}

/// Calculate the maximum C32 encoded output size given an input size.
/// Each C32 character encodes 5 bits.
pub fn get_max_c32_encode_output_len(input_len: usize) -> usize {
    let capacity = (input_len as f64 + (input_len % 5) as f64) / 5.0 * 8.0;
    capacity as usize
}

/// C32 encodes input bytes into an output buffer. Returns the number of bytes written to the
/// output buffer.
/// # Arguments
/// * `output_buffer` - A mutable slice where the C32 encoded bytes are written. An error
/// result is returned if the length is smaller than the maximum possible output length. Each
/// C32 character encodes 5 bits; use `get_max_c32_encode_output_len` to easily determine the
/// minimum length.
///
/// # Examples
///
/// ```
/// use stacks_encoding_native_js::address::c32::*;
/// let input_bytes = b"hello world";
/// let capacity = get_max_c32_encode_output_len(input_bytes.len());
/// let mut buffer: Vec<u8> = vec![0; capacity];
/// let bytes_written = c32_encode_to_buffer(input_bytes, &mut buffer).unwrap();
/// buffer.truncate(bytes_written);
/// String::from_utf8(buffer);
/// ```
pub fn c32_encode_to_buffer(input_bytes: &[u8], output_buffer: &mut [u8]) -> Result<usize, String> {
    let min_len = get_max_c32_encode_output_len(input_bytes.len());
    if output_buffer.len() < min_len {
        Err(format!(
            "C32 encode output buffer is too small, given size {}, need minimum size {}",
            output_buffer.len(),
            min_len
        ))?
    }
    let mut carry = 0;
    let mut carry_bits = 0;
    let mut position = 0;

    for current_value in input_bytes.iter().rev() {
        let low_bits_to_take = 5 - carry_bits;
        let low_bits = current_value & ((1 << low_bits_to_take) - 1);
        let c32_value = (low_bits << carry_bits) + carry;

        output_buffer[position] = C32_CHARACTERS[c32_value as usize];
        position += 1;

        carry_bits = (8 + carry_bits) - 5;
        carry = current_value >> (8 - carry_bits);

        if carry_bits >= 5 {
            let c32_value = carry & ((1 << 5) - 1);

            output_buffer[position] = C32_CHARACTERS[c32_value as usize];
            position += 1;

            carry_bits = carry_bits - 5;
            carry = carry >> 5;
        }
    }

    if carry_bits > 0 {
        output_buffer[position] = C32_CHARACTERS[carry as usize];
        position += 1;
    }

    // remove leading zeros from c32 encoding
    while position > 0 && output_buffer[position - 1] == C32_CHARACTERS[0] {
        position -= 1;
    }

    // add leading zeros from input.
    for current_value in input_bytes.iter() {
        if *current_value == 0 {
            output_buffer[position] = C32_CHARACTERS[0];
            position += 1;
        } else {
            break;
        }
    }

    output_buffer[..position].reverse();
    Ok(position)
}

#[allow(dead_code)]
fn c32_decode(input_str: &str) -> Result<Vec<u8>, String> {
    // must be ASCII
    if !input_str.is_ascii() {
        return Err("Invalid crockford 32 string".into());
    }
    c32_decode_ascii(input_str.as_bytes())
}

fn c32_decode_ascii(input_str: &[u8]) -> Result<Vec<u8>, String> {
    // let initial_capacity = 1 + ((input_str.len() * 5) / 8);
    let initial_capacity = input_str.len();
    let mut result = Vec::with_capacity(initial_capacity);
    let mut carry: u16 = 0;
    let mut carry_bits = 0; // can be up to 5

    let mut c32_digits = vec![0u8; input_str.len()];

    for (i, x) in input_str.iter().rev().enumerate() {
        c32_digits[i] = match C32_CHARACTERS_MAP.get(*x as usize) {
            Some(&Some(v)) => v,
            _ => Err("Invalid crockford 32 string".to_string())?,
        };
    }

    for current_5bit in &c32_digits {
        carry += (*current_5bit as u16) << carry_bits;
        carry_bits += 5;

        if carry_bits >= 8 {
            result.push((carry & ((1 << 8) - 1)) as u8);
            carry_bits -= 8;
            carry = carry >> 8;
        }
    }

    if carry_bits > 0 {
        result.push(carry as u8);
    }

    // remove leading zeros from Vec<u8> encoding
    let mut i = result.len();
    while i > 0 && result[i - 1] == 0 {
        i -= 1;
        result.truncate(i);
    }

    // add leading zeros from input.
    for current_value in c32_digits.iter().rev() {
        if *current_value == 0 {
            result.push(0);
        } else {
            break;
        }
    }

    result.reverse();
    Ok(result)
}

fn c32_check_encode_prefixed(version: u8, data: &[u8], prefix: u8) -> Result<Vec<u8>, String> {
    if version >= 32 {
        return Err(format!("Invalid version {}", version));
    }

    let data_len = data.len();
    let mut buffer: Vec<u8> = vec![0; data_len + 4];

    let checksum_buffer = Sha256::digest({
        Sha256::new()
            .chain_update(&[version])
            .chain_update(data)
            .finalize()
    });

    buffer[..data_len].copy_from_slice(data);
    buffer[data_len..(data_len + 4)].copy_from_slice(&checksum_buffer[0..4]);

    let capacity = get_max_c32_encode_output_len(buffer.len()) + 2;
    let mut result: Vec<u8> = vec![0; capacity];

    result[0] = prefix;
    result[1] = C32_CHARACTERS[version as usize];
    let bytes_written = c32_encode_to_buffer(&buffer, &mut result[2..])?;
    result.truncate(bytes_written + 2);
    Ok(result)
}

fn c32_check_decode<TOutput>(check_data_unsanitized: &str) -> Result<(u8, TOutput), String>
where
    TOutput: for<'a> TryFrom<&'a [u8]>,
{
    // must be ASCII
    if !check_data_unsanitized.is_ascii() {
        return Err("Invalid crockford 32 string, must be ascii".to_string());
    }

    if check_data_unsanitized.len() < 2 {
        return Err("Invalid crockford 32 string, size less than 2".to_string());
    }

    let ascii_bytes = check_data_unsanitized.as_bytes();
    let (version, data) = ascii_bytes.split_first().unwrap();

    let data_sum_bytes = c32_decode_ascii(data)?;
    if data_sum_bytes.len() < 4 {
        return Err("Invalid crockford 32 string, decoded byte length less than 4".to_string());
    }

    let (data_bytes, expected_sum) = data_sum_bytes.split_at(data_sum_bytes.len() - 4);
    let decoded_version = c32_decode_ascii(&[*version]).unwrap();
    let computed_sum = Sha256::digest(
        Sha256::new()
            .chain_update(&decoded_version)
            .chain_update(&data_bytes)
            .finalize(),
    );
    let checksum_ok = {
        computed_sum[0] == expected_sum[0]
            && computed_sum[1] == expected_sum[1]
            && computed_sum[2] == expected_sum[2]
            && computed_sum[3] == expected_sum[3]
    };
    if !checksum_ok {
        let computed_sum_u32 = (computed_sum[0] as u32)
            | ((computed_sum[1] as u32) << 8)
            | ((computed_sum[2] as u32) << 16)
            | ((computed_sum[3] as u32) << 24);

        let expected_sum_u32 = (expected_sum[0] as u32)
            | ((expected_sum[1] as u32) << 8)
            | ((expected_sum[2] as u32) << 16)
            | ((expected_sum[3] as u32) << 24);

        return Err(format!(
            "base58ck checksum 0x{:x} does not match expected 0x{:x}",
            computed_sum_u32, expected_sum_u32
        ));
    }

    let version = decoded_version[0];
    let data: TOutput = data_bytes
        .try_into()
        .map_err(|_| format!("Could not convert decoded c32 bytes"))?;
    Ok((version, data))
}

pub fn c32_address_decode(c32_address_str: &str) -> Result<(u8, [u8; 20]), String> {
    if c32_address_str.len() <= 5 {
        Err("Invalid crockford 32 string, address string smaller than 5 bytes".into())
    } else {
        c32_check_decode(&c32_address_str[1..])
    }
}

pub fn c32_address(version: u8, data: &[u8]) -> Result<String, String> {
    let bytes = c32_check_encode_prefixed(version, data, b'S')?;
    Ok(String::from_utf8(bytes).unwrap())
}

