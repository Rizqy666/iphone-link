//! Pure-Rust QR Code encoder for short pairing URLs.
//!
//! Scope (kept deliberately small so the module has no dependencies):
//! - ISO/IEC 18004 symbols, versions 1..=10
//! - Error-correction level **M**
//! - **Byte mode** only (the default encoding for ASCII URLs)
//! - All eight data masks, selected with the standard N1..N4 penalty rules
//!
//! The resulting [`QrMatrix`] can be rasterized with [`qr_to_rgba`] (for a
//! `wgpu`/`image` style RGBA8 texture) or serialized with [`qr_to_svg`].

/// A square QR symbol. `modules` is row-major (`row * size + col`);
/// `true` means a dark module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QrMatrix {
    pub size: usize,
    pub modules: Vec<bool>,
}

/// One group of blocks with an identical block size.
/// `(number of blocks, total codewords per block)`.
type BlockGroup = (usize, usize);

/// `(total codewords, EC codewords per block, groups)` for EC level M.
type EcParams = (usize, usize, &'static [BlockGroup]);

/// Standard EC-M block structure for versions 1 through 10.
///
/// The group sizes below satisfy, for every version:
/// `sum(count * total_per_block) == total_codewords`, and
/// `sum(count * (total_per_block - ec_per_block)) == total - ec_total`.
fn ec_params(version: usize) -> Option<EcParams> {
    match version {
        //  total, ec/block, groups (count, total per block)
        1 => Some((26, 10, &[(1, 26)])),
        2 => Some((44, 16, &[(1, 44)])),
        3 => Some((70, 26, &[(1, 70)])),
        4 => Some((100, 18, &[(2, 50)])),
        5 => Some((134, 24, &[(2, 67)])),
        6 => Some((172, 16, &[(4, 43)])),
        7 => Some((196, 18, &[(4, 49)])),
        8 => Some((242, 22, &[(2, 60), (2, 61)])),
        9 => Some((292, 22, &[(3, 58), (2, 59)])),
        10 => Some((346, 26, &[(4, 69), (1, 70)])),
        _ => None,
    }
}

fn data_codewords(params: EcParams) -> usize {
    let (_, ec_per_block, groups) = params;
    groups
        .iter()
        .map(|&(count, total)| count * (total - ec_per_block))
        .sum()
}

/// Number of bits in the byte-mode character count indicator.
fn count_bits(version: usize) -> usize {
    if version >= 10 {
        16
    } else {
        8
    }
}

/// Maximum number of byte-mode payload bytes for a version at EC level M.
fn byte_capacity(version: usize) -> usize {
    let params = ec_params(version).expect("version must be 1..=10");
    let bits = data_codewords(params) * 8;
    (bits - 4 - count_bits(version)) / 8
}

fn select_version(payload_len: usize) -> Result<(usize, EcParams), String> {
    for version in 1..=10 {
        if payload_len <= byte_capacity(version) {
            return Ok((version, ec_params(version).unwrap()));
        }
    }
    Err(format!(
        "QR payload too long: {} bytes; maximum for byte mode / EC-M with versions 1-10 is {} bytes",
        payload_len,
        byte_capacity(10)
    ))
}

/// Alignment-pattern center coordinates (ISO/IEC 18004 Table E.1).
fn alignment_positions(version: usize) -> Vec<usize> {
    match version {
        1 => Vec::new(),
        2 => vec![6, 18],
        3 => vec![6, 22],
        4 => vec![6, 26],
        5 => vec![6, 30],
        6 => vec![6, 34],
        7 => vec![6, 22, 38],
        8 => vec![6, 24, 42],
        9 => vec![6, 26, 46],
        10 => vec![6, 28, 50],
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// GF(256) arithmetic and Reed-Solomon
// ---------------------------------------------------------------------------

/// Multiply two GF(256) elements with primitive polynomial `x^8+x^4+x^3+x^2+1` (0x11D).
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high_bit_set = a & 0x80 != 0;
        a <<= 1;
        if high_bit_set {
            a ^= 0x1D; // reduce modulo 0x11D
        }
        b >>= 1;
    }
    product
}

/// `alpha^exponent`, where `alpha = 2` is a primitive element of GF(256).
fn gf_alpha_pow(exponent: usize) -> u8 {
    let mut value = 1u8;
    for _ in 0..exponent {
        value = gf_mul(value, 2);
    }
    value
}

/// Generator polynomial `prod_i (x - alpha^i)`, highest degree first.
fn rs_generator(degree: usize) -> Vec<u8> {
    let mut generator = vec![1u8];
    for i in 0..degree {
        let root = gf_alpha_pow(i);
        let mut next = vec![0u8; generator.len() + 1];
        for (j, &coefficient) in generator.iter().enumerate() {
            next[j] ^= coefficient; // multiply by x
            next[j + 1] ^= gf_mul(coefficient, root); // multiply by -alpha^i (char. 2)
        }
        generator = next;
    }
    generator
}

/// Reed-Solomon remainder (the error-correction codewords) for one block.
fn rs_remainder(data: &[u8], degree: usize) -> Vec<u8> {
    let generator = rs_generator(degree);
    let mut remainder = vec![0u8; degree];
    for &byte in data {
        let factor = byte ^ remainder[0];
        remainder.remove(0);
        remainder.push(0);
        for i in 0..degree {
            remainder[i] ^= gf_mul(generator[i + 1], factor);
        }
    }
    remainder
}

// ---------------------------------------------------------------------------
// Bit stream and codeword construction
// ---------------------------------------------------------------------------

fn append_bits(bits: &mut Vec<bool>, value: usize, length: usize) {
    for shift in (0..length).rev() {
        bits.push((value >> shift) & 1 != 0);
    }
}

fn build_codewords(text: &str, version: usize, params: EcParams) -> Result<Vec<u8>, String> {
    let (total_codewords, ec_per_block, groups) = params;
    let capacity = data_codewords(params);
    let max_bits = capacity * 8;
    let payload = text.as_bytes();

    let max_count = (1usize << count_bits(version)) - 1;
    if payload.len() > max_count {
        return Err(format!(
            "QR byte-mode payload length {} exceeds the {} bit character count indicator",
            payload.len(),
            count_bits(version)
        ));
    }

    // Mode indicator (0100), character count, payload, terminator, byte padding.
    let mut bits = Vec::with_capacity(max_bits);
    append_bits(&mut bits, 0b0100, 4);
    append_bits(&mut bits, payload.len(), count_bits(version));
    for &byte in payload {
        append_bits(&mut bits, byte as usize, 8);
    }
    for _ in 0..4 {
        if bits.len() < max_bits {
            bits.push(false);
        }
    }
    while bits.len() % 8 != 0 {
        bits.push(false);
    }

    let mut data = Vec::with_capacity(capacity);
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for &bit in chunk {
            byte = (byte << 1) | u8::from(bit);
        }
        data.push(byte);
    }
    let mut alternate = false;
    while data.len() < capacity {
        data.push(if alternate { 0x11 } else { 0xEC });
        alternate = !alternate;
    }

    // Split into blocks, compute EC per block, then interleave data and EC.
    let mut blocks: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(groups.iter().map(|g| g.0).sum());
    let mut offset = 0usize;
    for &(count, total) in groups {
        let data_len = total - ec_per_block;
        for _ in 0..count {
            let block_data = data[offset..offset + data_len].to_vec();
            offset += data_len;
            let ec = rs_remainder(&block_data, ec_per_block);
            blocks.push((block_data, ec));
        }
    }
    debug_assert_eq!(offset, data.len());

    let mut codewords = Vec::with_capacity(total_codewords);
    let longest_data = blocks.iter().map(|b| b.0.len()).max().unwrap_or(0);
    for i in 0..longest_data {
        for (block_data, _) in &blocks {
            if i < block_data.len() {
                codewords.push(block_data[i]);
            }
        }
    }
    for i in 0..ec_per_block {
        for (_, ec) in &blocks {
            codewords.push(ec[i]);
        }
    }
    debug_assert_eq!(codewords.len(), total_codewords);
    Ok(codewords)
}

// ---------------------------------------------------------------------------
// Matrix construction
// ---------------------------------------------------------------------------

/// BCH(15,5) format word for EC level M (format bits `00`) and `mask`.
///
/// Generator 0x537, XOR mask 0x5412. Bit 0 is the least significant bit.
fn format_bits(mask: usize) -> u16 {
    debug_assert!(mask < 8);
    let data = mask as u16; // EC-M contributes 0 to the two high bits
    let mut remainder = data;
    for _ in 0..10 {
        remainder = (remainder << 1) ^ if (remainder >> 9) & 1 != 0 { 0x537 } else { 0 };
    }
    ((data << 10) | (remainder & 0x03FF)) ^ 0x5412
}

/// BCH(18,6) version word (generator 0x1F25), used for versions >= 7.
fn version_bits(version: usize) -> u32 {
    let mut remainder = version as u32;
    for _ in 0..12 {
        remainder = (remainder << 1)
            ^ if (remainder >> 11) & 1 != 0 {
                0x1F25
            } else {
                0
            };
    }
    ((version as u32) << 12) | (remainder & 0x0FFF)
}

#[derive(Clone)]
struct QrBuilder {
    version: usize,
    size: usize,
    modules: Vec<bool>,
    is_function: Vec<bool>,
}

impl QrBuilder {
    fn new(version: usize) -> Self {
        let size = 21 + 4 * (version - 1);
        Self {
            version,
            size,
            modules: vec![false; size * size],
            is_function: vec![false; size * size],
        }
    }

    fn index(&self, row: usize, col: usize) -> usize {
        row * self.size + col
    }

    fn set_function(&mut self, row: usize, col: usize, dark: bool) {
        let i = self.index(row, col);
        self.modules[i] = dark;
        self.is_function[i] = true;
    }

    /// Draw all function patterns. Timing is drawn first so that finder and
    /// alignment patterns can overwrite it where they intersect (as required).
    fn draw_function_patterns(&mut self) {
        // Timing patterns: row 6 and column 6.
        for i in 0..self.size {
            self.set_function(6, i, i % 2 == 0);
            self.set_function(i, 6, i % 2 == 0);
        }

        // Three finder patterns (7x7) plus their one-module white separators.
        // Each finder is drawn as a 9x9 ring around its center at distance 4;
        // out-of-bounds cells are simply skipped.
        let centers = [(3usize, 3usize), (3, self.size - 4), (self.size - 4, 3)];
        for (center_row, center_col) in centers {
            for dr in -4i32..=4 {
                for dc in -4i32..=4 {
                    let row = center_row as i32 + dr;
                    let col = center_col as i32 + dc;
                    if row < 0 || col < 0 || row >= self.size as i32 || col >= self.size as i32 {
                        continue;
                    }
                    let distance = dr.abs().max(dc.abs());
                    // dark for distance 0,1 (core) and 3 (outer ring);
                    // light for 2 (inner ring) and 4 (separator).
                    self.set_function(row as usize, col as usize, distance != 2 && distance != 4);
                }
            }
        }

        // Alignment patterns (5x5), excluding the three finder corners.
        let positions = alignment_positions(self.version);
        let last = positions.len().saturating_sub(1);
        for (i, &row) in positions.iter().enumerate() {
            for (j, &col) in positions.iter().enumerate() {
                if (i == 0 && j == 0) || (i == 0 && j == last) || (i == last && j == 0) {
                    continue;
                }
                for dr in -2i32..=2 {
                    for dc in -2i32..=2 {
                        let distance = dr.abs().max(dc.abs());
                        self.set_function(
                            (row as i32 + dr) as usize,
                            (col as i32 + dc) as usize,
                            distance != 1,
                        );
                    }
                }
            }
        }

        // Format information is drawn with a placeholder mask here; it is
        // redrawn for each candidate mask during penalty evaluation.
        self.draw_format_info(0);
        self.draw_version_info();
    }

    /// Draw both copies of the 15-bit format word plus the fixed dark module.
    fn draw_format_info(&mut self, mask: usize) {
        let bits = format_bits(mask);
        let bit = |i: usize| (bits >> i) & 1 != 0;

        // Copy 1: around the top-left finder. Column 8 is used for bits 0..8
        // (skipping row 6, which is the timing pattern) and row 8 for the rest.
        for i in 0..=5 {
            self.set_function(i, 8, bit(i));
        }
        self.set_function(7, 8, bit(6));
        self.set_function(8, 8, bit(7));
        self.set_function(8, 7, bit(8));
        for i in 9..15 {
            self.set_function(8, 14 - i, bit(i));
        }

        // Copy 2: split between the top-right and bottom-left finders.
        for i in 0..8 {
            self.set_function(8, self.size - 1 - i, bit(i));
        }
        for i in 8..15 {
            self.set_function(self.size - 15 + i, 8, bit(i));
        }
        // The dark module is always dark and is not part of the format word.
        self.set_function(self.size - 8, 8, true);
    }

    /// Draw the two copies of the 18-bit version word (versions >= 7 only).
    fn draw_version_info(&mut self) {
        if self.version < 7 {
            return;
        }
        let bits = version_bits(self.version);
        for i in 0..18 {
            let dark = ((bits >> i) & 1) != 0;
            let a = self.size - 11 + i % 3;
            let b = i / 3;
            self.set_function(b, a, dark);
            self.set_function(a, b, dark);
        }
    }

    /// Place interleaved codewords in the standard upward/downward zig-zag,
    /// two columns at a time, skipping column 6 and all function modules.
    fn draw_codewords(&mut self, codewords: &[u8]) {
        let total_bits = codewords.len() * 8;
        let mut bit_index = 0usize;
        let mut right: isize = self.size as isize - 1;

        while right >= 1 {
            if right == 6 {
                right = 5; // skip the vertical timing column
            }
            let column_pair = right as usize;
            let upward = ((column_pair + 1) & 2) == 0;
            for vertical in 0..self.size {
                for offset in 0..2 {
                    let col = column_pair - offset;
                    let row = if upward {
                        self.size - 1 - vertical
                    } else {
                        vertical
                    };
                    let i = self.index(row, col);
                    if !self.is_function[i] && bit_index < total_bits {
                        self.modules[i] =
                            (codewords[bit_index >> 3] >> (7 - (bit_index & 7))) & 1 != 0;
                        bit_index += 1;
                    }
                }
            }
            right -= 2;
        }
        // Any unfilled data modules are remainder bits and stay light.
    }

    /// Apply mask `mask` to every non-function module.
    fn apply_mask(&mut self, mask: usize) {
        for row in 0..self.size {
            for col in 0..self.size {
                let i = self.index(row, col);
                if !self.is_function[i] && mask_bit(mask, row, col) {
                    self.modules[i] = !self.modules[i];
                }
            }
        }
    }

    /// Total N1 + N2 + N3 + N4 penalty for the current (fully drawn) matrix.
    fn penalty(&self) -> u32 {
        let n = self.size;
        let mut score = 0u32;

        // N1 (runs >= 5) and N3 (finder-like 1:1:3:1:1 patterns) on rows and columns.
        // 00001011101 = light area followed by the 1:1:3:1:1 pattern;
        // 10111010000 = the pattern followed by a light area.
        const LIGHT_THEN_PATTERN: [bool; 11] = [
            false, false, false, false, true, false, true, true, true, false, true,
        ];
        const PATTERN_THEN_LIGHT: [bool; 11] = [
            true, false, true, true, true, false, true, false, false, false, false,
        ];

        for orientation in 0..2 {
            for line in 0..n {
                let cell = |position: usize| {
                    if orientation == 0 {
                        line * n + position
                    } else {
                        position * n + line
                    }
                };

                // N1.
                let mut run_color = self.modules[cell(0)];
                let mut run_length = 1usize;
                for position in 1..n {
                    let color = self.modules[cell(position)];
                    if color == run_color {
                        run_length += 1;
                    } else {
                        if run_length >= 5 {
                            score += (3 + run_length - 5) as u32;
                        }
                        run_color = color;
                        run_length = 1;
                    }
                }
                if run_length >= 5 {
                    score += (3 + run_length - 5) as u32;
                }

                // N3 (40 points per occurrence).
                if n >= 11 {
                    for start in 0..=n - 11 {
                        let mut matches_light_first = true;
                        let mut matches_pattern_first = true;
                        for offset in 0..11 {
                            let value = self.modules[cell(start + offset)];
                            matches_light_first &= value == LIGHT_THEN_PATTERN[offset];
                            matches_pattern_first &= value == PATTERN_THEN_LIGHT[offset];
                        }
                        if matches_light_first || matches_pattern_first {
                            score += 40;
                        }
                    }
                }
            }
        }

        // N2: each monochromatic 2x2 block costs 3 points.
        for row in 0..n - 1 {
            for col in 0..n - 1 {
                let value = self.modules[self.index(row, col)];
                if value == self.modules[self.index(row, col + 1)]
                    && value == self.modules[self.index(row + 1, col)]
                    && value == self.modules[self.index(row + 1, col + 1)]
                {
                    score += 3;
                }
            }
        }

        // N4: 10 points for every 5% deviation from a 50% dark ratio.
        let dark = self.modules.iter().filter(|&&module| module).count();
        let total = n * n;
        let scaled_dark = dark * 100;
        let scaled_half = total * 50;
        let deviation = if scaled_dark > scaled_half {
            scaled_dark - scaled_half
        } else {
            scaled_half - scaled_dark
        };
        score += ((deviation / (total * 5)) * 10) as u32;

        score
    }
}

/// Standard QR mask condition for pattern `mask` at `(row, col)`.
fn mask_bit(mask: usize, row: usize, col: usize) -> bool {
    let (x, y) = (col, row);
    match mask {
        0 => (x + y) % 2 == 0,
        1 => y % 2 == 0,
        2 => x % 3 == 0,
        3 => (x + y) % 3 == 0,
        4 => (x / 3 + y / 2) % 2 == 0,
        5 => (x * y) % 2 + (x * y) % 3 == 0,
        6 => ((x * y) % 2 + (x * y) % 3) % 2 == 0,
        7 => ((x + y) % 2 + (x * y) % 3) % 2 == 0,
        _ => false,
    }
}

/// Encode `text` as an EC-M, byte-mode QR symbol, choosing the smallest
/// version (1 through 10) that fits the payload.
pub fn encode_qr(text: &str) -> Result<QrMatrix, String> {
    let payload_len = text.as_bytes().len();
    let (version, params) = select_version(payload_len)?;
    let codewords = build_codewords(text, version, params)?;

    // Build the function patterns and unmasked data once, then try all masks.
    let mut base = QrBuilder::new(version);
    base.draw_function_patterns();
    base.draw_codewords(&codewords);

    let mut best_penalty = u32::MAX;
    let mut best_modules = None;
    for mask in 0..8 {
        let mut candidate = base.clone();
        candidate.apply_mask(mask);
        candidate.draw_format_info(mask); // format bits depend on the chosen mask
        let penalty = candidate.penalty();
        if penalty < best_penalty {
            best_penalty = penalty;
            best_modules = Some(candidate.modules);
        }
    }

    Ok(QrMatrix {
        size: base.size,
        modules: best_modules.expect("there are always 8 mask candidates"),
    })
}

/// Rasterize a QR matrix into RGBA8 pixels, with `quiet` white modules of
/// border and each module drawn as a `scale x scale` block.
///
/// Returns `(rgba_bytes, width, height)`. White is `(255,255,255,255)` and
/// dark modules are `(0,0,0,255)`.
pub fn qr_to_rgba(
    matrix: &QrMatrix,
    scale: usize,
    quiet: usize,
) -> Result<(Vec<u8>, u32, u32), String> {
    if scale == 0 {
        return Err("QR scale must be at least 1".to_string());
    }
    // `quiet` is unsigned, so "quiet >= 0" is inherent; checked math below
    // rejects values that would overflow the image dimensions.
    if matrix.modules.len() != matrix.size * matrix.size {
        return Err(format!(
            "QR matrix has {} modules but size {} requires {}",
            matrix.modules.len(),
            matrix.size,
            matrix.size * matrix.size
        ));
    }

    let side = matrix
        .size
        .checked_add(quiet.checked_mul(2).ok_or("QR quiet zone is too large")?)
        .ok_or("QR image side length overflowed")?;
    let width = side.checked_mul(scale).ok_or("QR image width overflowed")?;
    let height = width; // the matrix is square
    let total_bytes = width
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or("QR image buffer size overflowed")?;

    // Start fully opaque white; only RGB channels of dark pixels are cleared.
    let mut rgba = vec![255u8; total_bytes];
    for row in 0..matrix.size {
        for col in 0..matrix.size {
            if !matrix.modules[row * matrix.size + col] {
                continue;
            }
            let start_y = (quiet + row) * scale;
            let start_x = (quiet + col) * scale;
            for y in start_y..start_y + scale {
                for x in start_x..start_x + scale {
                    let i = (y * width + x) * 4;
                    rgba[i] = 0;
                    rgba[i + 1] = 0;
                    rgba[i + 2] = 0;
                }
            }
        }
    }

    let to_u32 = |value: usize| -> Result<u32, String> {
        u32::try_from(value).map_err(|_| "QR image dimensions exceed u32".to_string())
    };
    Ok((rgba, to_u32(width)?, to_u32(height)?))
}

/// Minimal SVG representation of a matrix, with a white quiet zone.
pub fn qr_to_svg(matrix: &QrMatrix, quiet: usize) -> String {
    let side = matrix.size.saturating_add(quiet.saturating_mul(2));
    let mut svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {s} {s}\" shape-rendering=\"crispEdges\">",
        s = side
    );
    svg.push_str(&format!(
        "<rect width=\"{s}\" height=\"{s}\" fill=\"#ffffff\"/>",
        s = side
    ));
    svg.push_str("<g fill=\"#000000\">");
    for row in 0..matrix.size {
        for col in 0..matrix.size {
            if matrix.modules[row * matrix.size + col] {
                svg.push_str(&format!(
                    "<rect x=\"{}\" y=\"{}\" width=\"1\" height=\"1\"/>",
                    col + quiet,
                    row + quiet
                ));
            }
        }
    }
    svg.push_str("</g></svg>");
    svg
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_URL: &str = "http://192.168.1.10:8765/q?i=ABCD&c=123456&m=paired_macs";

    fn module(matrix: &QrMatrix, row: usize, col: usize) -> bool {
        matrix.modules[row * matrix.size + col]
    }

    /// Reconstruct the 15-bit format word from copy 1 in the matrix.
    fn read_format_copy_1(matrix: &QrMatrix) -> u16 {
        let bit = |row, col| u16::from(module(matrix, row, col));
        let mut bits = 0u16;
        for i in 0..=5 {
            bits |= bit(i, 8) << i;
        }
        bits |= bit(7, 8) << 6;
        bits |= bit(8, 8) << 7;
        bits |= bit(8, 7) << 8;
        for i in 9..15 {
            bits |= bit(8, 14 - i) << i;
        }
        bits
    }

    /// Reconstruct the 15-bit format word from copy 2 in the matrix.
    fn read_format_copy_2(matrix: &QrMatrix) -> u16 {
        let bit = |row, col| u16::from(module(matrix, row, col));
        let mut bits = 0u16;
        for i in 0..8 {
            bits |= bit(8, matrix.size - 1 - i) << i;
        }
        for i in 8..15 {
            bits |= bit(matrix.size - 15 + i, 8) << i;
        }
        bits
    }

    /// Minimal decoder used only to verify the encoder's placement, masking,
    /// interleaving, and bit packing in a round-trip test.
    fn decode_payload(matrix: &QrMatrix) -> String {
        let version = (matrix.size - 17) / 4;
        let (total, ec_per_block, groups) = ec_params(version).unwrap();

        // Function-module layout is independent of the mask value.
        let mut builder = QrBuilder::new(version);
        builder.draw_function_patterns();
        let mask = (0..8)
            .find(|&m| format_bits(m) == read_format_copy_1(matrix))
            .expect("valid format information");

        // Walk the same zig-zag, undoing the mask on data modules.
        let mut bits = Vec::new();
        let mut right: isize = matrix.size as isize - 1;
        while right >= 1 {
            if right == 6 {
                right = 5;
            }
            let column_pair = right as usize;
            let upward = ((column_pair + 1) & 2) == 0;
            for vertical in 0..matrix.size {
                for offset in 0..2 {
                    let col = column_pair - offset;
                    let row = if upward {
                        matrix.size - 1 - vertical
                    } else {
                        vertical
                    };
                    let i = row * matrix.size + col;
                    if !builder.is_function[i] {
                        let mut value = module(matrix, row, col);
                        if mask_bit(mask, row, col) {
                            value = !value;
                        }
                        bits.push(value);
                    }
                }
            }
            right -= 2;
        }

        let mut codewords = vec![0u8; total];
        for (i, &value) in bits.iter().take(total * 8).enumerate() {
            codewords[i >> 3] |= u8::from(value) << (7 - (i & 7));
        }

        // Undo block interleaving: first the data codewords, block by block.
        let data_lengths: Vec<usize> = groups
            .iter()
            .flat_map(|&(count, block_total)| (0..count).map(move |_| block_total - ec_per_block))
            .collect();
        let mut blocks = vec![Vec::new(); data_lengths.len()];
        let mut position = 0usize;
        let longest = *data_lengths.iter().max().unwrap();
        for i in 0..longest {
            for (block, &length) in data_lengths.iter().enumerate() {
                if i < length {
                    blocks[block].push(codewords[position]);
                    position += 1;
                }
            }
        }
        let data: Vec<u8> = blocks.into_iter().flatten().collect();

        // Parse byte-mode segment: 0100, character count, payload bytes.
        let mut bit_index = 0usize;
        let mut read = |length: usize| -> usize {
            let mut value = 0usize;
            for _ in 0..length {
                value =
                    (value << 1) | usize::from((data[bit_index >> 3] >> (7 - (bit_index & 7))) & 1);
                bit_index += 1;
            }
            value
        };
        assert_eq!(read(4), 0b0100);
        let length = read(count_bits(version));
        let payload: Vec<u8> = (0..length).map(|_| read(8) as u8).collect();
        String::from_utf8(payload).expect("ASCII payload")
    }

    #[test]
    fn format_info_for_ec_m_mask_zero_is_constant() {
        // EC level M has format bits 00, so data = 0 and the word is just the XOR mask.
        assert_eq!(format_bits(0), 0x5412);
        assert_eq!(format_bits(1), 0x5125);
    }

    #[test]
    fn version_info_bch_is_correct() {
        assert_eq!(version_bits(7), 0x07C94);
        assert_eq!(version_bits(10), 0x0A4D3);
    }

    #[test]
    fn finder_pattern_is_present_at_origin() {
        let matrix = encode_qr("hello").expect("encoding must succeed");
        // Center (3,3): the 5x5 core is dark, the ring at distance 2 is light,
        // the ring at distance 3 is dark, and row/col 7 are separators.
        assert!(module(&matrix, 0, 0));
        assert!(!module(&matrix, 1, 1));
        assert!(module(&matrix, 2, 2));
        assert!(module(&matrix, 3, 3));
        assert!(module(&matrix, 6, 6));
        assert!(!module(&matrix, 7, 7));
        // Fixed dark module.
        assert!(module(&matrix, matrix.size - 8, 8));
    }

    #[test]
    fn short_url_encodes_to_square_matrix_with_valid_format_info() {
        let matrix = encode_qr(TEST_URL).expect("URL must fit in version 10");
        assert_eq!(matrix.modules.len(), matrix.size * matrix.size);
        assert_eq!((matrix.size - 17) % 4, 0);
        let version = (matrix.size - 17) / 4;
        assert!((1..=10).contains(&version));

        let copy_1 = read_format_copy_1(&matrix);
        let copy_2 = read_format_copy_2(&matrix);
        assert_eq!(copy_1, copy_2);
        assert!((0..8).any(|mask| format_bits(mask) == copy_1));

        // Full round trip through placement, masking, RS interleaving, and bit packing.
        assert_eq!(decode_payload(&matrix), TEST_URL);
    }

    #[test]
    fn rgba_has_expected_size_and_pixels() {
        let matrix = encode_qr(TEST_URL).expect("URL must fit in version 10");
        let (rgba, width, height) = qr_to_rgba(&matrix, 3, 4).unwrap();
        assert_eq!(width as usize, (matrix.size + 8) * 3);
        assert_eq!(height, width);
        assert_eq!(rgba.len(), width as usize * height as usize * 4);

        // Quiet zone corner is opaque white.
        assert_eq!(&rgba[0..4], &[255u8, 255, 255, 255]);

        // First dark module maps to an opaque black pixel.
        let (row, col) = matrix
            .modules
            .iter()
            .enumerate()
            .find(|(_, &dark)| dark)
            .map(|(i, _)| (i / matrix.size, i % matrix.size))
            .expect("matrix has dark modules");
        let y = (4 + row) * 3;
        let x = (4 + col) * 3;
        let pixel = (y * width as usize + x) * 4;
        assert_eq!(&rgba[pixel..pixel + 4], &[0u8, 0, 0, 255]);

        assert!(qr_to_rgba(&matrix, 0, 4).is_err());
    }

    #[test]
    fn svg_contains_white_background_and_modules() {
        let matrix = encode_qr("qr").unwrap();
        let svg = qr_to_svg(&matrix, 4);
        assert!(svg.starts_with("<svg "));
        assert!(svg.contains("fill=\"#ffffff\""));
        assert!(svg.ends_with("</svg>"));
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let payload = "x".repeat(byte_capacity(10) + 1);
        let error = encode_qr(&payload).expect_err("payload must not fit");
        assert!(error.contains("too long"), "unexpected error: {}", error);
    }

    #[test]
    fn ec_m_group_tables_are_consistent() {
        for version in 1..=10 {
            let (total, ec_per_block, groups) = ec_params(version).unwrap();
            let summed_total: usize = groups.iter().map(|&(count, size)| count * size).sum();
            let summed_data: usize = groups
                .iter()
                .map(|&(count, size)| count * (size - ec_per_block))
                .sum();
            assert_eq!(summed_total, total, "version {}", version);
            assert_eq!(
                summed_data + groups.iter().map(|g| g.0).sum::<usize>() * ec_per_block,
                total,
                "version {}",
                version
            );
        }
    }
}
