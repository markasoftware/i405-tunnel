/**
 * Very simple "I405 Padding Protocol". The stream starts with an 8-byte magic value. Then, there's
 * a single-byte length indicating how many following bytes are application data. Then, the next
 * byte is a single-byte length for the next chunk of application data. This allows arbitrary
 * padding because if one of the length bytes is 0 it effectively acts as padding.
 */

const I405PP_MAGIC_VALUE_LEN: usize = 8;
const I405PP_MAGIC_VALUE: [u8; I405PP_MAGIC_VALUE_LEN] =
    [0x01, 0x04, 0x00, 0x05, 0x01, 0x04, 0x00, 0x05];

#[derive(Debug)]
pub struct I405PPDecoder {
    // these fit in u8 but i can't imagine it will be faster
    num_magic_bytes_left: usize,
    num_chunk_bytes_left: usize,
}

impl I405PPDecoder {
    pub fn new() -> Self {
        Self {
            num_magic_bytes_left: I405PP_MAGIC_VALUE_LEN,
            num_chunk_bytes_left: 0,
        }
    }

    /// Push some bytes through, get the bytes that should come out. The only possible error is the
    /// magic values not matching. Returns the portion of `out_bytes` that was populated, on
    /// success. Input will always be fully consumed.
    pub fn pump(&mut self, bytes: &[u8], out_bytes: &mut [u8]) -> Result<usize, ()> {
        assert!(
            out_bytes.len() >= bytes.len(),
            "out_bytes must be at least as large as in_bytes"
        );

        let mut out_i: usize = 0;
        for i in 0..bytes.len() {
            if self.num_magic_bytes_left > 0 {
                if bytes[i]
                    != I405PP_MAGIC_VALUE[I405PP_MAGIC_VALUE_LEN - self.num_magic_bytes_left]
                {
                    return Err(());
                }
                self.num_magic_bytes_left -= 1;
            } else if self.num_chunk_bytes_left > 0 {
                out_bytes[out_i] = bytes[i];
                out_i += 1;
                self.num_chunk_bytes_left -= 1;
            } else {
                // self.num_chunk_bytes_left == 0
                self.num_chunk_bytes_left = usize::from(bytes[i]);
            }
        }

        return Ok(out_i);
    }
}

#[derive(Debug)]
pub struct I405PPEncoder {
    num_magic_bytes_left: usize,
    num_chunk_bytes_left: usize,
}

impl I405PPEncoder {
    pub fn new() -> Self {
        Self {
            num_magic_bytes_left: I405PP_MAGIC_VALUE_LEN,
            num_chunk_bytes_left: 0,
        }
    }

    /// Completely fills `out_bytes` with encoded data generated from `bytes`, adding padding if
    /// necessary. Returns the number of `bytes` consumed.
    pub fn pump(&mut self, bytes: &[u8], out_bytes: &mut [u8]) -> usize {
        let mut in_i: usize = 0;
        for out_i in 0..out_bytes.len() {
            if self.num_magic_bytes_left > 0 {
                out_bytes[out_i] =
                    I405PP_MAGIC_VALUE[I405PP_MAGIC_VALUE_LEN - self.num_magic_bytes_left];
                self.num_magic_bytes_left -= 1;
            } else if self.num_chunk_bytes_left > 0 {
                assert!(
                    in_i < bytes.len(),
                    "Ran out of data encoding a chunk. `pump` must have been called multiple times, with the `bytes` passed the second time being inconsistent with those passed the first time."
                );
                out_bytes[out_i] = bytes[in_i];
                in_i += 1;
                self.num_chunk_bytes_left -= 1;
            } else {
                // num_chunk_bytes_left == 0
                // I hope try_from compiles down to no-op here
                // this will gracefully do padding: If in_i == bytes.len(), it'll just be zero!
                let next_chunk_size =
                    u8::try_from(std::cmp::min(0xFF, bytes.len() - in_i)).unwrap();
                out_bytes[out_i] = next_chunk_size;
                self.num_chunk_bytes_left = usize::from(next_chunk_size);
            }
        }

        return in_i;
    }
}

#[cfg(test)]
mod tests {
    use super::{I405PPDecoder, I405PPEncoder};

    /// Roundtrips with a single big chunk
    fn assert_roundtrip_one_chunk(bytes: &[u8]) {
        let mut encoder = I405PPEncoder::new();
        let mut decoder = I405PPDecoder::new();

        let generous_intermediate_size = bytes.len() * 2 + 10; // enough room for the magic value plus magic vals
        let mut intermediate_bytes = vec![0; generous_intermediate_size];

        let num_encoder_consumed_bytes = encoder.pump(bytes, intermediate_bytes.as_mut_slice());
        assert_eq!(num_encoder_consumed_bytes, bytes.len());

        let mut final_bytes = vec![0; generous_intermediate_size];
        let num_decoder_bytes_produced = decoder
            .pump(intermediate_bytes.as_slice(), final_bytes.as_mut_slice())
            .unwrap();
        assert_eq!(num_decoder_bytes_produced, bytes.len());
        assert_eq!(bytes, &final_bytes.as_slice()[0..bytes.len()]);
    }

    /// return number of chunks
    fn assert_roundtrip_chunked(bytes: &[u8], chunk_size: usize) -> u32 {
        let mut encoder = I405PPEncoder::new();
        let mut decoder = I405PPDecoder::new();

        let mut final_bytes = vec![0; bytes.len() + chunk_size];

        let mut encoder_consumed_bytes = 0;
        let mut decoder_produced_bytes = 0;
        let mut num_chunks = 0;
        while encoder_consumed_bytes < bytes.len() {
            let chunk = &bytes[encoder_consumed_bytes..];
            let mut intermediate_bytes = vec![0; chunk_size];
            encoder_consumed_bytes += encoder.pump(chunk, intermediate_bytes.as_mut_slice());
            let final_bytes_slice = &mut final_bytes.as_mut_slice()[decoder_produced_bytes..];
            decoder_produced_bytes += decoder
                .pump(intermediate_bytes.as_slice(), final_bytes_slice)
                .unwrap();
            num_chunks += 1;
        }
        assert_eq!(encoder_consumed_bytes, bytes.len());
        assert_eq!(decoder_produced_bytes, bytes.len());
        assert_eq!(bytes, &final_bytes.as_slice()[0..bytes.len()]);
        return num_chunks;
    }

    #[test]
    fn roundtrip_one_chunk() {
        assert_roundtrip_one_chunk(&[]);
        assert_roundtrip_one_chunk(&[0x01, 0x02, 0x03, 0x04]);

        let mut big_vec = Vec::<u8>::new();
        for i in 0..1000 {
            big_vec.push(u8::try_from(i % 0xFF).unwrap());
        }
        assert_roundtrip_one_chunk(big_vec.as_slice());
    }

    #[test]
    fn roundtrip_multiple_chunks() {
        assert_eq!(assert_roundtrip_chunked(&[0x42], 2), 5);
        assert_eq!(assert_roundtrip_chunked(&[0x42], 8), 2);
        assert_eq!(assert_roundtrip_chunked(&[0x42], 10), 1);
        let mut big_vec = Vec::<u8>::new();
        for i in 0..1000 {
            big_vec.push(u8::try_from(i % 0xFF).unwrap());
        }
        assert_eq!(assert_roundtrip_chunked(big_vec.as_slice(), 500), 3);
        // 8 byte magic + 1000 byte data + 4 lengths
        assert_eq!(assert_roundtrip_chunked(big_vec.as_slice(), 1011), 2);
        assert_eq!(assert_roundtrip_chunked(big_vec.as_slice(), 1012), 1);
    }
}
