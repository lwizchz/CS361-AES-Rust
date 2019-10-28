extern crate structopt;

use std::fmt;

use structopt::StructOpt;
use std::str::FromStr;

use std::fs::File;
use std::io::prelude::*;

const NUM_COL: usize = 4; // Nb
const NUM_WORDS_128: usize = 4; // Nk for 128bit
const NUM_WORDS_256: usize = 8; // Nk for 256bit
const NUM_ROUNDS_128: usize = 10; // Nr for 128bit
const NUM_ROUNDS_256: usize = 14; // Nr for 256bit

const BLOCK_SIZE: usize = 16;

#[derive(Debug)]
pub enum Error {
    Parse(String),
    IO(String),
    KeyGen(String),
//    Encrypt(String),
//    Decrypt(String),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}
impl std::convert::From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::IO(format!("{:?}", err))
    }
}

pub enum Keysize {
    B128,
    B256,
}
impl FromStr for Keysize {
    type Err = Error;
    fn from_str(keysize: &str) -> Result<Self, Self::Err> {
        match keysize {
            "128" => Ok(Keysize::B128),
            "256" => Ok(Keysize::B256),
            _ => Err(Error::Parse(format!("Couldn't parse keysize: {}", keysize)))
        }
    }
}

pub enum Mode {
    Encrypt,
    Decrypt,
}
impl FromStr for Mode {
    type Err = Error;
    fn from_str(mode: &str) -> Result<Self, Self::Err> {
        match mode {
            "encrypt" => Ok(Mode::Encrypt),
            "decrypt" => Ok(Mode::Decrypt),
            _ => Err(Error::Parse(format!("Couldn't parse mode: {}", mode)))
        }
    }
}

#[derive(StructOpt)]
#[structopt(name = "yoink", about = "A cool new yoinker")]
pub struct Opt {
    #[structopt(short = "s", long, default_value = "128")]
    pub keysize: Keysize,
    #[structopt(short, long, default_value = "encrypt")]
    pub mode: Mode,
    #[structopt(short, long)]
    pub verbose: bool,

    #[structopt(short, long)]
    pub keyfile: String,
    #[structopt(short, long)]
    pub inputfile: String,
    #[structopt(short, long)]
    pub outputfile: String,
}

pub type State = [[u8; NUM_COL]; 4];
#[derive(Clone, Debug, PartialEq)]
pub struct StateArray {
    states: Vec<State>,
    total_bytes: usize,
}
pub type Word = [u8; 4];
pub type Key = Vec<Word>;
pub struct KeySchedule {
    schedule: Vec<Word>,
}

const AES_SBOX: [[u8; 16]; 16] = [
    /*       0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f   */
    /* 0 */ [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    /* 1 */ [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    /* 2 */ [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    /* 3 */ [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    /* 4 */ [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    /* 5 */ [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    /* 6 */ [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    /* 7 */ [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    /* 8 */ [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    /* 9 */ [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    /* a */ [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    /* b */ [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    /* c */ [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    /* d */ [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    /* e */ [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    /* f */ [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16],
];
const AES_INV_SBOX: [[u8; 16]; 16] = [
    /*       0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f   */
    /* 0 */ [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
    /* 1 */ [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
    /* 2 */ [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
    /* 3 */ [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
    /* 4 */ [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
    /* 5 */ [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
    /* 6 */ [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
    /* 7 */ [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
    /* 8 */ [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
    /* 9 */ [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
    /* a */ [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
    /* b */ [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
    /* c */ [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
    /* d */ [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
    /* e */ [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
    /* f */ [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d],
];
const AES_IRREDUCIBLE: u16 = 0x011b; // The irreducible polynomial m(x) = x^8 + x^4 + x^3 + x + 1
const RCON: [u8; 10] = [
//  1       2       3       4       5       6       7       8       9       10
    0x01,   0x02,   0x04,   0x08,   0x10,   0x20,   0x40,   0x80,   0x1b,   0x36
];

trait StateMethods {
    fn print(&self, block_and_size: Option<(usize, usize)>);
}
impl StateMethods for State {
    fn print(&self, block_and_bytes: Option<(usize, usize)>) {
        let (block, total_bytes) = match block_and_bytes {
            Some((bl, tb)) => {
                (bl, tb)
            },
            None => {
                (0, BLOCK_SIZE)
            },
        };

        for r in 0..4 {
            for c in 0..NUM_COL {
                if block*BLOCK_SIZE + r+4*c >= total_bytes {
                    print!("xx ");
                } else {
                    print!("{:02x} ", self[r][c]);
                }
            }
            println!();
        }
    }
}

impl StateArray {
    pub fn from_file(filename: &str) -> Result<Self, Error> {
        let fh = File::open(filename)?;
        let total_bytes = fh.metadata()?.len() as usize;
        let states_needed: usize = (total_bytes as f32 / BLOCK_SIZE as f32).ceil() as usize;
        let mut bytes = fh.bytes();

        let mut states = Vec::with_capacity(states_needed);

        let mut failed_reads = 0;
        for _ in 0..states_needed {
            let mut current_state: State = [[0; NUM_COL]; 4];

            for c in 0..NUM_COL {
                for r in 0..4 {
                    match bytes.next() {
                        Some(b) => {
                            current_state[r][c] = b?;
                        },
                        None => {
                            failed_reads += 1;
                            if failed_reads > BLOCK_SIZE {
                                return Err(Error::IO(format!("Failed to read file: {}", filename)));
                            }
                        }
                    }
                }
            }

            states.push(current_state);
        }

        Ok(StateArray {
            states: states,
            total_bytes: total_bytes,
        })
    }

    pub fn print(&self) {
        let mut blocks: usize = 0;

        for state in &self.states {
            state.print(Some((blocks, self.total_bytes)));
            println!();
            blocks += 1;
        }
    }

    pub fn write(&self, filename: &str) -> Result<usize, Error> {
        let mut fh = File::create(filename)?;
        let mut bytes_written = 0;

        for state in &self.states {
            for c in 0..NUM_COL {
                for r in 0..4 {
                    fh.write_all(&[state[r][c]])?;
                    bytes_written += 1;

                    if bytes_written >= self.total_bytes {
                        return Ok(bytes_written);
                    }
                }
            }
        }

        Ok(bytes_written)
    }
}
impl fmt::Display for StateArray {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl KeySchedule {
    pub fn generate(keyfile: &str, keysize: &Keysize) -> Result<Self, Error> {
        let raw_key: Key = Self::read_key(keyfile, keysize)?;

        Self::key_expansion(raw_key, keysize)
    }

    pub fn print(&self) {
        let mut blocks: usize = 0;

        for w in &self.schedule {
            for r in 0..4 {
                print!("{:02x} ", w[r]);
            }
            println!();

            blocks += 1;
            if blocks % 4 == 0 {
                println!();
            }
        }
    }

    fn read_key(filename: &str, keysize: &Keysize) -> Result<Key, Error> {
        let fh = File::open(filename)?;
        let mut bytes = fh.bytes();

        let bytes_needed: usize = match keysize {
            Keysize::B128 => 16,
            Keysize::B256 => 32,
        };
        let words_needed: usize = bytes_needed / 4;

        let mut key: Key = Vec::with_capacity(words_needed);
        for _ in 0..words_needed {
            let mut word = [0; 4];
            for c in 0..4 {
                match bytes.next() {
                    Some(b) => {
                        word[c] = b?;
                    },
                    None => {
                        return Err(Error::KeyGen(format!("Failed to read keyfile: {}", filename)));
                    },
                }
            }
            key.push(word);
        }

        Ok(key)
    }

    fn key_expansion(raw_key: Key, keysize: &Keysize) -> Result<Self, Error> {
        let num_words = match keysize {
            Keysize::B128 => NUM_WORDS_128,
            Keysize::B256 => NUM_WORDS_256,
        };
        let num_rounds = match keysize {
            Keysize::B128 => NUM_ROUNDS_128,
            Keysize::B256 => NUM_ROUNDS_256,
        };

        let mut schedule = Vec::with_capacity(NUM_COL * num_rounds);

        for i in 0..num_words {
            schedule.push(raw_key[i]);
        }
        for i in num_words..(NUM_COL * (num_rounds+1)) {
            let mut temp = schedule[i-1].clone();
            if i % num_words == 0 {
                let rotw = Self::rot_word(temp);
                let subw = Self::sub_word(rotw);
                let rcon = Self::rcon(i / num_words)?;
                let xorw = Self::xor_word(subw, rcon);
                temp = xorw;
            } else if num_words > 6 && i % num_words == 4 {
                temp = Self::sub_word(temp);
            }
            let xor_tmp = Self::xor_word(schedule[i - num_words].clone(), temp);
            schedule.push(xor_tmp);
        }

        Ok(KeySchedule {
            schedule: schedule
        })
    }
    fn rcon(i: usize) -> Result<Word, Error> {
        if i < 1 || i > 10 {
            return Err(Error::KeyGen(format!("Invalid word section: {}", i)))
        }

        Ok([
            RCON[i-1], 0, 0, 0
        ])
    }
    fn rot_word(w: Word) -> Word {
        [
            w[1], w[2], w[3], w[0]
        ]
    }
    fn sub_word(mut w: Word) -> Word {
        for r in 0..4 {
            let sbox_col_idx = (w[r] & 0x0f) as usize;
            let sbox_row_idx = ((w[r] & 0xf0) >> 4) as usize;
            w[r] = AES_SBOX[sbox_row_idx][sbox_col_idx];
        }

        w
    }
    fn xor_word(lhs: Word, rhs: Word) -> Word {
        [
            lhs[0] ^ rhs[0],
            lhs[1] ^ rhs[1],
            lhs[2] ^ rhs[2],
            lhs[3] ^ rhs[3],
        ]
    }
}

fn aes_add(a: u8, b: u8) -> u8 {
    a ^ b
}
fn aes_mult(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0x0;
    }

    let mut r: u8 = 0;
    for i in 0..8 {
        // Conditionally add the multiplication by 0x02<<i
        if b & (0x1<<i) != 0x0 {
            r = aes_add(r, xtime(a.clone(), i));
        }
    }

    r
}
fn xtime(mut a: u8, x: usize) -> u8 {
    if x == 0 {
        return a;
    }

    // Conditionally add of the irreducible polynomial 0x011b to reduce a*0x02
    if a & 0x80 != 0x0 {
        a = aes_add(a<<1, (AES_IRREDUCIBLE & 0xff) as u8); // FIXME: only 1 byte used?
    } else {
        a <<= 1;
    }

    xtime(a, x-1)
}

/*
* add_round_key: XOR the state with a 128-bit round key
* derived from the original key K by a recursive process.
*
* The input text (state) is represented as a 4x4 array of bytes.
* The key is represented as a 4xN array of bytes,
* where N depends on the key size (10 or 14).
*/
fn add_round_key(state: &mut State, partial_schedule: &[Word]) {
    assert!(partial_schedule.len() == NUM_COL);

    for r in 0..4 {
        for c in 0..NUM_COL {
            state[r][c] = aes_add(state[r][c], partial_schedule[c][r])
        }
    }
}
fn sub_bytes(state: &mut State) {
    for r in 0..4 {
        for c in 0..NUM_COL {
            let sbox_col_idx = (state[r][c] & 0x0f) as usize;
            let sbox_row_idx = ((state[r][c] & 0xf0) >> 4) as usize;
            state[r][c] = AES_SBOX[sbox_row_idx][sbox_col_idx];
        }
    }
}
// All row shifts are left cyclically
fn shift_rows(state: &mut State) {
    // Do nothing to Row 0

    // Shift Row 1 by 1
    let s1_0: u8 = state[1][0];
    for c in 0..3 {
        state[1][c] = state[1][c + 1];
    }
    state[1][3] = s1_0;

    // Shift Row 2 by 2
    let s2_0: u8 = state[2][0];
    let s2_1: u8 = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = s2_0;
    state[2][3] = s2_1;

    // Shift Row 3 by 3
    let s3_0: u8 = state[3][0];
    let s3_1: u8 = state[3][1];
    let s3_2: u8 = state[3][2];
    state[3][0] = state[3][3];
    state[3][1] = s3_0;
    state[3][2] = s3_1;
    state[3][3] = s3_2;
}
fn mix_columns(state: &mut State) {
    for c in 0..NUM_COL {
        // Store bytes for computation
        let s0: u8 = state[0][c];
        let s1: u8 = state[1][c];
        let s2: u8 = state[2][c];
        let s3: u8 = state[3][c];

        // Compute bytes according to the AES specification
        state[0][c] = aes_add(
            aes_add(
                aes_mult(0x02, s0),
                aes_mult(0x03, s1)
            ),
            aes_add(s2, s3)
        );
        state[1][c] = aes_add(
            aes_add(
                s0,
                aes_mult(0x02, s1)
            ),
            aes_add(
                aes_mult(0x03, s2),
                s3
            )
        );
        state[2][c] = aes_add(
            aes_add(s0, s1),
            aes_add(
                aes_mult(0x02, s2),
                aes_mult(0x03, s3)
            )
        );
        state[3][c] = aes_add(
            aes_add(
                aes_mult(0x03, s0),
                s1
            ),
            aes_add(
                s2,
                aes_mult(0x02, s3)
            )
        );
    }
}

// All row shifts are right cyclically
fn inv_shift_rows(state: &mut State) {
    // Do nothing to Row 0

    // Shift Row 1 by 1
    let s1_3: u8 = state[1][3];
    for c in (1..4).rev() {
        state[1][c] = state[1][c-1];
    }
    state[1][0] = s1_3;

    // Shift Row 2 by 2
    let s2_0: u8 = state[2][0];
    let s2_1: u8 = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = s2_0;
    state[2][3] = s2_1;

    // Shift Row 3 by 3
    let s3_0: u8 = state[3][0];
    for c in 0..3 {
        state[3][c] = state[3][c+1];
    }
    state[3][3] = s3_0;

}
fn inv_sub_bytes(state: &mut State) {
    for r in 0..4 {
        for c in 0..NUM_COL {
            let inv_sbox_col_idx: usize = (state[r][c] & 0x0f) as usize;
            let inv_sbox_row_idx: usize = ((state[r][c] & 0xf0) >> 4) as usize;
            state[r][c] = AES_INV_SBOX[inv_sbox_row_idx][inv_sbox_col_idx];
        }
    }
}
fn inv_mix_columns(state: &mut State) {
    for c in 0..NUM_COL {
        // Store bytes for computation
        let s0: u8 = state[0][c];
        let s1: u8 = state[1][c];
        let s2: u8 = state[2][c];
        let s3: u8 = state[3][c];

        // Compute bytes according to the AES specification
        state[0][c] = aes_add(
            aes_add(
                aes_mult(0x0e, s0),
                aes_mult(0x0b, s1)
            ),
            aes_add(
                aes_mult(0x0d, s2),
                aes_mult(0x09, s3)
            )
        );
        state[1][c] = aes_add(
            aes_add(
                aes_mult(0x09, s0),
                aes_mult(0x0e, s1)
            ),
            aes_add(
                aes_mult(0x0b, s2),
                aes_mult(0x0d, s3)
            )
        );
        state[2][c] = aes_add(
            aes_add(
                aes_mult(0x0d, s0),
                aes_mult(0x09, s1)
            ),
            aes_add(
                aes_mult(0x0e, s2),
                aes_mult(0x0b, s3)
            )
        );
        state[3][c] = aes_add(
            aes_add(
                aes_mult(0x0b, s0),
                aes_mult(0x0d, s1)
            ),
            aes_add(
                aes_mult(0x09, s2),
                aes_mult(0x0e, s3)
            )
        );
    }
}

pub fn encrypt(keysize: &Keysize, input: &StateArray, schedule: &KeySchedule) -> Result<StateArray, Error> {
    let mut output: StateArray = input.clone();

    // Add padding
    let rem = input.total_bytes % BLOCK_SIZE;
    let arrays_needed = (input.total_bytes as f32 / BLOCK_SIZE as f32).ceil() as usize;
    if rem == 0 {
        // Add empty block
        let mut empty_state: State = [[0; NUM_COL]; 4];
        empty_state[3][3] = BLOCK_SIZE as u8;
        output.states.push(empty_state);
    } else {
        for c in 0..NUM_COL {
            for r in 0..4 {
                if r + 4*c >= rem {
                    output.states[arrays_needed - 1][r][c] = 0;
                }
            }
        }
        output.states[arrays_needed - 1][3][3] = (BLOCK_SIZE - rem) as u8;
    }
    output.total_bytes += BLOCK_SIZE - rem;

    // Run cipher
    let n_r: usize = match keysize {
        Keysize::B128 => NUM_ROUNDS_128,
        Keysize::B256 => NUM_ROUNDS_256,
    };
    for mut state in &mut output.states {
        add_round_key(&mut state, &schedule.schedule[0..NUM_COL]);

        for r in 1..n_r {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &schedule.schedule[(r * NUM_COL) .. ((r+1) * NUM_COL)]);
        }

        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &schedule.schedule[(n_r * NUM_COL) .. ((n_r+1) * NUM_COL)]);
    }

    Ok(output)
}
pub fn decrypt(keysize: &Keysize, input: &StateArray, schedule: &KeySchedule) -> Result<StateArray, Error> {
    let mut output: StateArray = input.clone();

    // Run cipher
    let n_r: usize = match keysize {
        Keysize::B128 => NUM_ROUNDS_128,
        Keysize::B256 => NUM_ROUNDS_256,
    };
    for mut state in &mut output.states {
        add_round_key(&mut state, &schedule.schedule[(n_r * NUM_COL) .. ((n_r+1) * NUM_COL)]);

        for r in (1 .. n_r).rev() {
            inv_shift_rows(&mut state);
            inv_sub_bytes(&mut state);
            add_round_key(&mut state, &schedule.schedule[(r*NUM_COL) .. ((r+1)*NUM_COL)]);
            inv_mix_columns(&mut state);
        }

        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &schedule.schedule[0..NUM_COL]);
    }

    // Remove padding
    let arrays_needed = (output.total_bytes as f32 / BLOCK_SIZE as f32).floor() as usize;
    let padded_bytes = output.states[arrays_needed-1][3][3];
    if padded_bytes as usize == BLOCK_SIZE {
        // Remove empty block
        output.states.pop();
        output.total_bytes -= BLOCK_SIZE;
    } else {
        output.total_bytes -= padded_bytes as usize;

        let rem = output.total_bytes % BLOCK_SIZE;
        for c in 0..NUM_COL {
            for r in 0..4 {
                if r + 4*c >= rem {
                    output.states[arrays_needed - 1][r][c] = 0;
                }
            }
        }
    }

    Ok(output)
}

pub fn do_with_args(args: &Opt) -> Result<StateArray, Error> {
    let input = StateArray::from_file(&args.inputfile)?;
    if args.verbose {
        println!("Input:\n");
        input.print();
        println!("---\n");
    }

    let schedule = KeySchedule::generate(&args.keyfile, &args.keysize)?;
    if args.verbose {
        println!("Keyschedule:\n");
        schedule.print();
        println!("---\n");
    }

    let output: StateArray = match args.mode {
        Mode::Encrypt => {
            encrypt(&args.keysize, &input, &schedule)?
        },
        Mode::Decrypt => {
            decrypt(&args.keysize, &input, &schedule)?
        },
    };

    if args.verbose {
        println!("Output:\n");
        output.print();
        println!("---\n");
    }
    if !args.outputfile.is_empty() {
        output.write(&args.outputfile)?;
    }

    Ok(output)
}
