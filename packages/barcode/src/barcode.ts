import type { BuiltinHandler } from "@wiredwp/robinpath";
import { writeFileSync } from "node:fs";

// ============================================================================
// Pure JavaScript QR Code Encoder
// Supports versions 1-10, error correction levels L/M/Q/H,
// numeric, alphanumeric, and byte encoding modes.
// ============================================================================

// --- Constants & Tables ---

const EC_LEVELS: Record<string, number> = { L: 0, M: 1, Q: 2, H: 3 };

// Mode indicators (4-bit)
const MODE_NUMERIC = 0b0001;
const MODE_ALPHANUMERIC = 0b0010;
const MODE_BYTE = 0b0100;

// Alphanumeric character table
const ALPHANUM_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

// Character count indicator bit lengths per version group [1-9, 10-26, 27-40]
const CHAR_COUNT_BITS: Record<number, number[]> = {
  [MODE_NUMERIC]: [10, 12, 14],
  [MODE_ALPHANUMERIC]: [9, 11, 13],
  [MODE_BYTE]: [8, 16, 16],
};

// QR version information: [totalCodewords, [ecCodewordsPerBlock], [numBlocks(group1), dataCodewordsPerBlock(group1), numBlocks(group2), dataCodewordsPerBlock(group2)]]
// Indexed by [version-1][ecLevel]
interface VersionECInfo {
  totalDataCodewords: number;
  ecCodewordsPerBlock: number;
  group1Blocks: number;
  group1DataCW: number;
  group2Blocks: number;
  group2DataCW: number;
}

// Total codewords per version (data + ec)
const TOTAL_CODEWORDS = [
  26, 44, 70, 100, 134, 172, 196, 242, 292, 346,
];

// Version/EC level table: [totalDataCodewords, ecCWPerBlock, g1Blocks, g1DataCW, g2Blocks, g2DataCW]
// Sources: ISO/IEC 18004 Table 9
const VERSION_EC_TABLE: number[][][] = [
  // Version 1
  [[19, 7, 1, 19, 0, 0], [16, 10, 1, 16, 0, 0], [13, 13, 1, 13, 0, 0], [9, 17, 1, 9, 0, 0]],
  // Version 2
  [[34, 10, 1, 34, 0, 0], [28, 16, 1, 28, 0, 0], [22, 22, 1, 22, 0, 0], [16, 28, 1, 16, 0, 0]],
  // Version 3
  [[55, 15, 1, 55, 0, 0], [44, 26, 1, 44, 0, 0], [34, 18, 2, 17, 0, 0], [24, 22, 2, 12, 0, 0]],
  // Version 4
  [[80, 20, 1, 80, 0, 0], [64, 18, 2, 32, 0, 0], [48, 26, 2, 24, 0, 0], [36, 16, 4, 9, 0, 0]],
  // Version 5
  [[108, 26, 1, 108, 0, 0], [86, 24, 2, 43, 0, 0], [62, 18, 2, 15, 2, 16], [46, 22, 2, 11, 2, 12]],
  // Version 6
  [[136, 18, 2, 68, 0, 0], [108, 16, 4, 27, 0, 0], [76, 24, 4, 19, 0, 0], [60, 28, 4, 15, 0, 0]],
  // Version 7
  [[156, 20, 2, 78, 0, 0], [124, 18, 4, 31, 0, 0], [88, 18, 2, 14, 4, 15], [66, 26, 4, 13, 1, 14]],
  // Version 8
  [[194, 24, 2, 97, 0, 0], [154, 22, 2, 38, 2, 39], [110, 22, 4, 18, 2, 19], [86, 26, 4, 14, 2, 15]],
  // Version 9
  [[232, 30, 2, 116, 0, 0], [182, 22, 3, 36, 2, 37], [132, 20, 4, 16, 4, 17], [100, 24, 4, 12, 4, 13]],
  // Version 10
  [[271, 18, 2, 68, 2, 69], [216, 26, 4, 43, 1, 44], [154, 24, 6, 19, 2, 20], [122, 28, 6, 15, 2, 16]],
];

// Alignment pattern positions per version (version 1 has none)
const ALIGNMENT_POSITIONS: number[][] = [
  [],         // v1
  [6, 18],    // v2
  [6, 22],    // v3
  [6, 26],    // v4
  [6, 30],    // v5
  [6, 34],    // v6
  [6, 22, 38],// v7
  [6, 24, 42],// v8
  [6, 26, 46],// v9
  [6, 28, 50],// v10
];

// Format information strings (15 bits) for each EC level and mask pattern
// Pre-calculated with BCH error correction
const FORMAT_INFO_STRINGS: number[][] = [
  // L (0)
  [0x77c4, 0x72f3, 0x7daa, 0x789d, 0x662f, 0x6318, 0x6c41, 0x6976],
  // M (1)
  [0x5412, 0x5125, 0x5e7c, 0x5b4b, 0x45f9, 0x40ce, 0x4f97, 0x4aa0],
  // Q (2)
  [0x355f, 0x3068, 0x3f31, 0x3a06, 0x24b4, 0x2183, 0x2eda, 0x2bed],
  // H (3)
  [0x1689, 0x13be, 0x1ce7, 0x19d0, 0x0762, 0x0255, 0x0d0c, 0x083b],
];

// --- Reed-Solomon Error Correction ---

// GF(256) with primitive polynomial 0x11d (x^8 + x^4 + x^3 + x^2 + 1)
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);

function initGaloisField(): void {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x >= 256) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) {
    GF_EXP[i] = GF_EXP[i - 255];
  }
}
initGaloisField();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function rsGeneratorPoly(numECCodewords: number): Uint8Array {
  let gen = new Uint8Array([1]);
  for (let i = 0; i < numECCodewords; i++) {
    const newGen = new Uint8Array(gen.length + 1);
    for (let j = 0; j < gen.length; j++) {
      newGen[j] ^= gen[j];
      newGen[j + 1] ^= gfMul(gen[j], GF_EXP[i]);
    }
    gen = newGen;
  }
  return gen;
}

function rsEncode(data: Uint8Array, numECCodewords: number): Uint8Array {
  const gen = rsGeneratorPoly(numECCodewords);
  const result = new Uint8Array(data.length + numECCodewords);
  result.set(data);

  for (let i = 0; i < data.length; i++) {
    const coef = result[i];
    if (coef !== 0) {
      for (let j = 0; j < gen.length; j++) {
        result[i + j] ^= gfMul(gen[j], coef);
      }
    }
  }

  return result.slice(data.length);
}

// --- Data Encoding ---

function detectMode(text: string): number {
  if (/^\d+$/.test(text)) return MODE_NUMERIC;
  if (text.split("").every((c) => ALPHANUM_CHARS.includes(c))) return MODE_ALPHANUMERIC;
  return MODE_BYTE;
}

function getCharCountBits(mode: number, version: number): number {
  const group = version <= 9 ? 0 : version <= 26 ? 1 : 2;
  return CHAR_COUNT_BITS[mode][group];
}

function getVersionECInfo(version: number, ecLevel: number): VersionECInfo {
  const row = VERSION_EC_TABLE[version - 1][ecLevel];
  return {
    totalDataCodewords: row[0],
    ecCodewordsPerBlock: row[1],
    group1Blocks: row[2],
    group1DataCW: row[3],
    group2Blocks: row[4],
    group2DataCW: row[5],
  };
}

function selectVersion(text: string, mode: number, ecLevel: number): number {
  const dataLen = mode === MODE_BYTE ? new TextEncoder().encode(text).length : text.length;
  for (let v = 1; v <= 10; v++) {
    const info = getVersionECInfo(v, ecLevel);
    const totalBits = info.totalDataCodewords * 8;
    const ccBits = getCharCountBits(mode, v);
    let dataBits: number;
    if (mode === MODE_NUMERIC) {
      dataBits = Math.floor(dataLen / 3) * 10 + (dataLen % 3 === 2 ? 7 : dataLen % 3 === 1 ? 4 : 0);
    } else if (mode === MODE_ALPHANUMERIC) {
      dataBits = Math.floor(dataLen / 2) * 11 + (dataLen % 2) * 6;
    } else {
      dataBits = dataLen * 8;
    }
    const needed = 4 + ccBits + dataBits;
    if (needed <= totalBits) return v;
  }
  throw new Error("Data too long for QR versions 1-10");
}

class BitBuffer {
  private bits: number[] = [];
  get length(): number { return this.bits.length; }

  put(value: number, numBits: number): void {
    for (let i = numBits - 1; i >= 0; i--) {
      this.bits.push((value >> i) & 1);
    }
  }

  getByte(index: number): number {
    let byte = 0;
    for (let i = 0; i < 8; i++) {
      const bitIndex = index * 8 + i;
      if (bitIndex < this.bits.length) {
        byte = (byte << 1) | this.bits[bitIndex];
      } else {
        byte <<= 1;
      }
    }
    return byte;
  }
}

function encodeData(text: string, version: number, ecLevel: number): Uint8Array {
  const mode = detectMode(text);
  const info = getVersionECInfo(version, ecLevel);
  const totalDataCodewords = info.totalDataCodewords;

  const buffer = new BitBuffer();

  // Mode indicator
  buffer.put(mode, 4);

  // Character count
  const ccBits = getCharCountBits(mode, version);

  if (mode === MODE_NUMERIC) {
    buffer.put(text.length, ccBits);
    for (let i = 0; i < text.length; i += 3) {
      const group = text.substring(i, i + 3);
      const bits = group.length === 3 ? 10 : group.length === 2 ? 7 : 4;
      buffer.put(parseInt(group, 10), bits);
    }
  } else if (mode === MODE_ALPHANUMERIC) {
    buffer.put(text.length, ccBits);
    for (let i = 0; i < text.length; i += 2) {
      if (i + 1 < text.length) {
        const val = ALPHANUM_CHARS.indexOf(text[i]) * 45 + ALPHANUM_CHARS.indexOf(text[i + 1]);
        buffer.put(val, 11);
      } else {
        buffer.put(ALPHANUM_CHARS.indexOf(text[i]), 6);
      }
    }
  } else {
    const bytes = new TextEncoder().encode(text);
    buffer.put(bytes.length, ccBits);
    for (const b of bytes) {
      buffer.put(b, 8);
    }
  }

  // Terminator
  const totalBits = totalDataCodewords * 8;
  const terminatorLen = Math.min(4, totalBits - buffer.length);
  buffer.put(0, terminatorLen);

  // Pad to byte boundary
  while (buffer.length % 8 !== 0) {
    buffer.put(0, 1);
  }

  // Pad codewords
  const padPatterns = [0xec, 0x11];
  let padIdx = 0;
  while (buffer.length < totalBits) {
    buffer.put(padPatterns[padIdx], 8);
    padIdx = 1 - padIdx;
  }

  // Convert to bytes
  const data = new Uint8Array(totalDataCodewords);
  for (let i = 0; i < totalDataCodewords; i++) {
    data[i] = buffer.getByte(i);
  }

  return data;
}

// --- Error Correction & Interleaving ---

function generateECCodewords(data: Uint8Array, version: number, ecLevel: number): Uint8Array {
  const info = getVersionECInfo(version, ecLevel);
  const { ecCodewordsPerBlock, group1Blocks, group1DataCW, group2Blocks, group2DataCW } = info;
  const totalCodewords = TOTAL_CODEWORDS[version - 1];

  const dataBlocks: Uint8Array[] = [];
  const ecBlocks: Uint8Array[] = [];
  let offset = 0;

  // Group 1
  for (let i = 0; i < group1Blocks; i++) {
    const block = data.slice(offset, offset + group1DataCW);
    dataBlocks.push(block);
    ecBlocks.push(rsEncode(block, ecCodewordsPerBlock));
    offset += group1DataCW;
  }

  // Group 2
  for (let i = 0; i < group2Blocks; i++) {
    const block = data.slice(offset, offset + group2DataCW);
    dataBlocks.push(block);
    ecBlocks.push(rsEncode(block, ecCodewordsPerBlock));
    offset += group2DataCW;
  }

  // Interleave data codewords
  const result: number[] = [];
  const maxDataCW = Math.max(group1DataCW, group2DataCW || 0);
  for (let i = 0; i < maxDataCW; i++) {
    for (const block of dataBlocks) {
      if (i < block.length) result.push(block[i]);
    }
  }

  // Interleave EC codewords
  for (let i = 0; i < ecCodewordsPerBlock; i++) {
    for (const block of ecBlocks) {
      if (i < block.length) result.push(block[i]);
    }
  }

  // Remainder bits are handled during matrix placement
  const output = new Uint8Array(totalCodewords);
  for (let i = 0; i < Math.min(result.length, totalCodewords); i++) {
    output[i] = result[i];
  }
  return output;
}

// --- QR Matrix Construction ---

function getModuleCount(version: number): number {
  return version * 4 + 17;
}

type QRMatrix = (number | null)[][];

function createMatrix(size: number): QRMatrix {
  return Array.from({ length: size }, () => Array(size).fill(null));
}

function placeFinderPattern(matrix: QRMatrix, row: number, col: number): void {
  for (let r = -1; r <= 7; r++) {
    for (let c = -1; c <= 7; c++) {
      const mr = row + r;
      const mc = col + c;
      if (mr < 0 || mr >= matrix.length || mc < 0 || mc >= matrix.length) continue;
      if (
        (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
        (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
        (r >= 2 && r <= 4 && c >= 2 && c <= 4)
      ) {
        matrix[mr][mc] = 1;
      } else {
        matrix[mr][mc] = 0;
      }
    }
  }
}

function placeAlignmentPattern(matrix: QRMatrix, row: number, col: number): void {
  for (let r = -2; r <= 2; r++) {
    for (let c = -2; c <= 2; c++) {
      if (Math.abs(r) === 2 || Math.abs(c) === 2 || (r === 0 && c === 0)) {
        matrix[row + r][col + c] = 1;
      } else {
        matrix[row + r][col + c] = 0;
      }
    }
  }
}

function placeTimingPatterns(matrix: QRMatrix): void {
  const size = matrix.length;
  for (let i = 8; i < size - 8; i++) {
    if (matrix[6][i] === null) matrix[6][i] = i % 2 === 0 ? 1 : 0;
    if (matrix[i][6] === null) matrix[i][6] = i % 2 === 0 ? 1 : 0;
  }
}

function reserveFormatInfo(matrix: QRMatrix): void {
  const size = matrix.length;
  // Around top-left finder
  for (let i = 0; i <= 8; i++) {
    if (matrix[8][i] === null) matrix[8][i] = 0;
    if (matrix[i][8] === null) matrix[i][8] = 0;
  }
  // Around top-right finder
  for (let i = 0; i <= 7; i++) {
    if (matrix[8][size - 1 - i] === null) matrix[8][size - 1 - i] = 0;
  }
  // Around bottom-left finder
  for (let i = 0; i <= 7; i++) {
    if (matrix[size - 1 - i][8] === null) matrix[size - 1 - i][8] = 0;
  }
  // Dark module
  matrix[size - 8][8] = 1;
}

function placeAllPatterns(matrix: QRMatrix, version: number): void {
  const size = matrix.length;

  // Finder patterns
  placeFinderPattern(matrix, 0, 0);
  placeFinderPattern(matrix, 0, size - 7);
  placeFinderPattern(matrix, size - 7, 0);

  // Alignment patterns (version 2+)
  if (version >= 2) {
    const positions = ALIGNMENT_POSITIONS[version - 1];
    for (const r of positions) {
      for (const c of positions) {
        // Skip if overlapping with finder patterns
        if (r <= 8 && c <= 8) continue; // top-left
        if (r <= 8 && c >= size - 8) continue; // top-right
        if (r >= size - 8 && c <= 8) continue; // bottom-left
        placeAlignmentPattern(matrix, r, c);
      }
    }
  }

  // Timing patterns
  placeTimingPatterns(matrix);

  // Reserve format info areas
  reserveFormatInfo(matrix);
}

function placeData(matrix: QRMatrix, data: Uint8Array): void {
  const size = matrix.length;
  let bitIndex = 0;
  const totalBits = data.length * 8;

  // Data placement goes right-to-left in 2-column strips, alternating up and down
  let col = size - 1;
  let goingUp = true;

  while (col >= 0) {
    // Skip column 6 (timing pattern)
    if (col === 6) col--;

    for (let row = 0; row < size; row++) {
      const actualRow = goingUp ? size - 1 - row : row;

      for (let c = 0; c < 2; c++) {
        const actualCol = col - c;
        if (actualCol < 0) continue;
        if (matrix[actualRow][actualCol] !== null) continue;

        if (bitIndex < totalBits) {
          const byteIndex = Math.floor(bitIndex / 8);
          const bitOffset = 7 - (bitIndex % 8);
          matrix[actualRow][actualCol] = (data[byteIndex] >> bitOffset) & 1;
          bitIndex++;
        } else {
          matrix[actualRow][actualCol] = 0;
        }
      }
    }

    goingUp = !goingUp;
    col -= 2;
  }
}

// --- Masking ---

function getMaskFunction(pattern: number): (row: number, col: number) => boolean {
  switch (pattern) {
    case 0: return (r, c) => (r + c) % 2 === 0;
    case 1: return (r) => r % 2 === 0;
    case 2: return (_, c) => c % 3 === 0;
    case 3: return (r, c) => (r + c) % 3 === 0;
    case 4: return (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
    case 5: return (r, c) => ((r * c) % 2 + (r * c) % 3) === 0;
    case 6: return (r, c) => ((r * c) % 2 + (r * c) % 3) % 2 === 0;
    case 7: return (r, c) => ((r + c) % 2 + (r * c) % 3) % 2 === 0;
    default: return (r, c) => (r + c) % 2 === 0;
  }
}

function isDataModule(matrix: QRMatrix, patternMatrix: QRMatrix, row: number, col: number): boolean {
  return patternMatrix[row][col] === null;
}

function applyMask(matrix: QRMatrix, patternMatrix: QRMatrix, maskPattern: number): QRMatrix {
  const size = matrix.length;
  const masked = matrix.map((row) => [...row]);
  const maskFn = getMaskFunction(maskPattern);

  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (isDataModule(matrix, patternMatrix, r, c)) {
        if (maskFn(r, c)) {
          masked[r][c] = masked[r][c] === 1 ? 0 : 1;
        }
      }
    }
  }

  return masked;
}

function writeFormatInfo(matrix: QRMatrix, ecLevel: number, maskPattern: number): void {
  const size = matrix.length;
  const formatBits = FORMAT_INFO_STRINGS[ecLevel][maskPattern];

  // Place format info bits
  // Horizontal strip near top-left
  const positions1: [number, number][] = [
    [8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8],
    [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8],
  ];

  // Second copy
  const positions2: [number, number][] = [];
  for (let i = 0; i < 7; i++) positions2.push([size - 1 - i, 8]);
  for (let i = 0; i < 8; i++) positions2.push([8, size - 8 + i]);

  for (let i = 0; i < 15; i++) {
    const bit = (formatBits >> (14 - i)) & 1;
    const [r1, c1] = positions1[i];
    matrix[r1][c1] = bit;
    const [r2, c2] = positions2[i];
    matrix[r2][c2] = bit;
  }
}

// --- Penalty scoring ---

function calculatePenalty(matrix: QRMatrix): number {
  const size = matrix.length;
  let penalty = 0;

  // Rule 1: Groups of 5+ same-colored modules in a row/column
  for (let r = 0; r < size; r++) {
    let count = 1;
    for (let c = 1; c < size; c++) {
      if (matrix[r][c] === matrix[r][c - 1]) {
        count++;
        if (c === size - 1 && count >= 5) penalty += count - 2;
      } else {
        if (count >= 5) penalty += count - 2;
        count = 1;
      }
    }
  }
  for (let c = 0; c < size; c++) {
    let count = 1;
    for (let r = 1; r < size; r++) {
      if (matrix[r][c] === matrix[r - 1][c]) {
        count++;
        if (r === size - 1 && count >= 5) penalty += count - 2;
      } else {
        if (count >= 5) penalty += count - 2;
        count = 1;
      }
    }
  }

  // Rule 2: 2x2 blocks of same color
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const val = matrix[r][c];
      if (val === matrix[r][c + 1] && val === matrix[r + 1][c] && val === matrix[r + 1][c + 1]) {
        penalty += 3;
      }
    }
  }

  // Rule 3: Finder-like patterns
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size - 10; c++) {
      if (
        matrix[r][c] === 1 && matrix[r][c + 1] === 0 && matrix[r][c + 2] === 1 &&
        matrix[r][c + 3] === 1 && matrix[r][c + 4] === 1 && matrix[r][c + 5] === 0 &&
        matrix[r][c + 6] === 1 && matrix[r][c + 7] === 0 && matrix[r][c + 8] === 0 &&
        matrix[r][c + 9] === 0 && matrix[r][c + 10] === 0
      ) penalty += 40;
      if (
        matrix[r][c] === 0 && matrix[r][c + 1] === 0 && matrix[r][c + 2] === 0 &&
        matrix[r][c + 3] === 0 && matrix[r][c + 4] === 1 && matrix[r][c + 5] === 0 &&
        matrix[r][c + 6] === 1 && matrix[r][c + 7] === 1 && matrix[r][c + 8] === 1 &&
        matrix[r][c + 9] === 0 && matrix[r][c + 10] === 1
      ) penalty += 40;
    }
  }
  for (let c = 0; c < size; c++) {
    for (let r = 0; r < size - 10; r++) {
      if (
        matrix[r][c] === 1 && matrix[r + 1][c] === 0 && matrix[r + 2][c] === 1 &&
        matrix[r + 3][c] === 1 && matrix[r + 4][c] === 1 && matrix[r + 5][c] === 0 &&
        matrix[r + 6][c] === 1 && matrix[r + 7][c] === 0 && matrix[r + 8][c] === 0 &&
        matrix[r + 9][c] === 0 && matrix[r + 10][c] === 0
      ) penalty += 40;
      if (
        matrix[r][c] === 0 && matrix[r + 1][c] === 0 && matrix[r + 2][c] === 0 &&
        matrix[r + 3][c] === 0 && matrix[r + 4][c] === 1 && matrix[r + 5][c] === 0 &&
        matrix[r + 6][c] === 1 && matrix[r + 7][c] === 1 && matrix[r + 8][c] === 1 &&
        matrix[r + 9][c] === 0 && matrix[r + 10][c] === 1
      ) penalty += 40;
    }
  }

  // Rule 4: Proportion of dark modules
  let darkCount = 0;
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (matrix[r][c] === 1) darkCount++;
    }
  }
  const percent = (darkCount / (size * size)) * 100;
  const prevFive = Math.floor(percent / 5) * 5;
  const nextFive = prevFive + 5;
  penalty += Math.min(Math.abs(prevFive - 50) / 5, Math.abs(nextFive - 50) / 5) * 10;

  return penalty;
}

// --- Main QR Code Generation ---

function generateQRMatrix(text: string, ecLevelStr: string = "M"): QRMatrix {
  const ecLevel = EC_LEVELS[ecLevelStr.toUpperCase()] ?? 1;
  const mode = detectMode(text);
  const version = selectVersion(text, mode, ecLevel);
  const size = getModuleCount(version);

  // Encode data
  const data = encodeData(text, version, ecLevel);

  // Generate error correction and interleave
  const codewords = generateECCodewords(data, version, ecLevel);

  // Create pattern template (for knowing which modules are data vs pattern)
  const patternMatrix = createMatrix(size);
  placeAllPatterns(patternMatrix, version);

  // Create actual matrix with patterns + data
  const baseMatrix = createMatrix(size);
  placeAllPatterns(baseMatrix, version);
  placeData(baseMatrix, codewords);

  // Try all 8 mask patterns, pick best
  let bestMask = 0;
  let bestPenalty = Infinity;
  let bestMatrix: QRMatrix = baseMatrix;

  for (let mask = 0; mask < 8; mask++) {
    const masked = applyMask(baseMatrix, patternMatrix, mask);
    writeFormatInfo(masked, ecLevel, mask);
    const penalty = calculatePenalty(masked);
    if (penalty < bestPenalty) {
      bestPenalty = penalty;
      bestMask = mask;
      bestMatrix = masked;
    }
  }

  // Apply best mask to fresh copy
  const finalMatrix = applyMask(baseMatrix, patternMatrix, bestMask);
  writeFormatInfo(finalMatrix, ecLevel, bestMask);

  return finalMatrix;
}

// --- Output Formats ---

function matrixToSvg(matrix: QRMatrix, opts: { width?: number; margin?: number; darkColor?: string; lightColor?: string } = {}): string {
  const moduleCount = matrix.length;
  const margin = opts.margin ?? 4;
  const width = opts.width ?? (moduleCount + margin * 2);
  const scale = width / (moduleCount + margin * 2);
  const darkColor = opts.darkColor ?? "#000000";
  const lightColor = opts.lightColor ?? "#ffffff";

  let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${moduleCount + margin * 2} ${moduleCount + margin * 2}" width="${width}" height="${width}" shape-rendering="crispEdges">`;
  svg += `<rect width="100%" height="100%" fill="${lightColor}"/>`;

  for (let r = 0; r < moduleCount; r++) {
    for (let c = 0; c < moduleCount; c++) {
      if (matrix[r][c] === 1) {
        svg += `<rect x="${c + margin}" y="${r + margin}" width="1" height="1" fill="${darkColor}"/>`;
      }
    }
  }

  svg += "</svg>";
  return svg;
}

function matrixToTerminal(matrix: QRMatrix): string {
  const moduleCount = matrix.length;
  const margin = 2;
  const lines: string[] = [];

  // Use Unicode block characters: upper half block, lower half block, full block
  // Each character row represents 2 module rows
  // White on white = space, Black on black = full block
  // Black on white = upper half, White on black = lower half

  const totalRows = moduleCount + margin * 2;
  const totalCols = moduleCount + margin * 2;

  const getModule = (r: number, c: number): boolean => {
    const mr = r - margin;
    const mc = c - margin;
    if (mr < 0 || mr >= moduleCount || mc < 0 || mc >= moduleCount) return false;
    return matrix[mr][mc] === 1;
  };

  for (let r = 0; r < totalRows; r += 2) {
    let line = "";
    for (let c = 0; c < totalCols; c++) {
      const top = getModule(r, c);
      const bottom = r + 1 < totalRows ? getModule(r + 1, c) : false;

      if (top && bottom) {
        line += "\u2588"; // Full block
      } else if (top && !bottom) {
        line += "\u2580"; // Upper half block
      } else if (!top && bottom) {
        line += "\u2584"; // Lower half block
      } else {
        line += " ";
      }
    }
    lines.push(line);
  }

  return lines.join("\n");
}

// --- Minimal PNG encoder (uncompressed, no dependencies) ---

function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function adler32(data: Uint8Array): number {
  let a = 1;
  let b = 0;
  for (let i = 0; i < data.length; i++) {
    a = (a + data[i]) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

function deflateStored(data: Uint8Array): Uint8Array {
  // Use stored (uncompressed) deflate blocks
  // Each block: 1 byte header + 2 bytes len + 2 bytes nlen + data
  const maxBlockSize = 65535;
  const numBlocks = Math.ceil(data.length / maxBlockSize) || 1;
  const output: number[] = [];

  for (let i = 0; i < numBlocks; i++) {
    const start = i * maxBlockSize;
    const end = Math.min(start + maxBlockSize, data.length);
    const block = data.slice(start, end);
    const isLast = i === numBlocks - 1;

    output.push(isLast ? 0x01 : 0x00); // BFINAL + BTYPE=00 (stored)
    const len = block.length;
    output.push(len & 0xff, (len >> 8) & 0xff);
    output.push((~len) & 0xff, ((~len) >> 8) & 0xff);
    for (let j = 0; j < block.length; j++) {
      output.push(block[j]);
    }
  }

  return new Uint8Array(output);
}

function createZlibData(rawData: Uint8Array): Uint8Array {
  const deflated = deflateStored(rawData);
  const adler = adler32(rawData);
  const result = new Uint8Array(2 + deflated.length + 4);
  // Zlib header: CMF=0x78, FLG=0x01 (no dict, level 0)
  result[0] = 0x78;
  result[1] = 0x01;
  result.set(deflated, 2);
  // Adler32 checksum (big-endian)
  const off = 2 + deflated.length;
  result[off] = (adler >> 24) & 0xff;
  result[off + 1] = (adler >> 16) & 0xff;
  result[off + 2] = (adler >> 8) & 0xff;
  result[off + 3] = adler & 0xff;
  return result;
}

function pngChunk(type: string, data: Uint8Array): Uint8Array {
  const typeBytes = new TextEncoder().encode(type);
  const chunk = new Uint8Array(4 + 4 + data.length + 4);
  // Length (big-endian)
  const len = data.length;
  chunk[0] = (len >> 24) & 0xff;
  chunk[1] = (len >> 16) & 0xff;
  chunk[2] = (len >> 8) & 0xff;
  chunk[3] = len & 0xff;
  // Type
  chunk.set(typeBytes, 4);
  // Data
  chunk.set(data, 8);
  // CRC over type + data
  const crcData = new Uint8Array(4 + data.length);
  crcData.set(typeBytes, 0);
  crcData.set(data, 4);
  const crc = crc32(crcData);
  chunk[8 + data.length] = (crc >> 24) & 0xff;
  chunk[9 + data.length] = (crc >> 16) & 0xff;
  chunk[10 + data.length] = (crc >> 8) & 0xff;
  chunk[11 + data.length] = crc & 0xff;
  return chunk;
}

function matrixToPng(matrix: QRMatrix, opts: { scale?: number; margin?: number } = {}): Uint8Array {
  const moduleCount = matrix.length;
  const scale = opts.scale ?? 10;
  const margin = opts.margin ?? 4;
  const totalModules = moduleCount + margin * 2;
  const imgSize = totalModules * scale;

  // Build raw image data (1-bit indexed, but we'll use grayscale for simplicity)
  // Each row: filter byte (0) + pixel data
  const rawData = new Uint8Array((1 + imgSize) * imgSize);

  for (let py = 0; py < imgSize; py++) {
    const rowOffset = py * (1 + imgSize);
    rawData[rowOffset] = 0; // No filter

    const moduleRow = Math.floor(py / scale) - margin;

    for (let px = 0; px < imgSize; px++) {
      const moduleCol = Math.floor(px / scale) - margin;

      let isDark = false;
      if (moduleRow >= 0 && moduleRow < moduleCount && moduleCol >= 0 && moduleCol < moduleCount) {
        isDark = matrix[moduleRow][moduleCol] === 1;
      }

      rawData[rowOffset + 1 + px] = isDark ? 0 : 255;
    }
  }

  // Create PNG
  const PNG_SIGNATURE = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);

  // IHDR
  const ihdr = new Uint8Array(13);
  ihdr[0] = (imgSize >> 24) & 0xff;
  ihdr[1] = (imgSize >> 16) & 0xff;
  ihdr[2] = (imgSize >> 8) & 0xff;
  ihdr[3] = imgSize & 0xff;
  ihdr[4] = (imgSize >> 24) & 0xff;
  ihdr[5] = (imgSize >> 16) & 0xff;
  ihdr[6] = (imgSize >> 8) & 0xff;
  ihdr[7] = imgSize & 0xff;
  ihdr[8] = 8;  // Bit depth
  ihdr[9] = 0;  // Color type: grayscale
  ihdr[10] = 0; // Compression
  ihdr[11] = 0; // Filter
  ihdr[12] = 0; // Interlace

  // IDAT
  const compressedData = createZlibData(rawData);

  // IEND
  const iendData = new Uint8Array(0);

  const chunks = [
    PNG_SIGNATURE,
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", compressedData),
    pngChunk("IEND", iendData),
  ];

  const totalLen = chunks.reduce((sum, c) => sum + c.length, 0);
  const png = new Uint8Array(totalLen);
  let offset = 0;
  for (const chunk of chunks) {
    png.set(chunk, offset);
    offset += chunk.length;
  }

  return png;
}

function matrixToDataUrl(matrix: QRMatrix, opts: { scale?: number; margin?: number } = {}): string {
  const png = matrixToPng(matrix, opts);
  // Manual base64 encoding
  const base64 = uint8ArrayToBase64(png);
  return `data:image/png;base64,${base64}`;
}

function uint8ArrayToBase64(bytes: Uint8Array): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let result = "";
  const len = bytes.length;

  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < len ? bytes[i + 1] : 0;
    const b2 = i + 2 < len ? bytes[i + 2] : 0;

    result += chars[(b0 >> 2) & 0x3f];
    result += chars[((b0 << 4) | (b1 >> 4)) & 0x3f];
    result += i + 1 < len ? chars[((b1 << 2) | (b2 >> 6)) & 0x3f] : "=";
    result += i + 2 < len ? chars[b2 & 0x3f] : "=";
  }

  return result;
}

// --- Parse options helper ---

interface QROptions {
  width?: number;
  margin?: number;
  scale?: number;
  errorCorrectionLevel?: string;
  color?: { dark?: string; light?: string };
}

function parseQROptions(opts: unknown): QROptions {
  if (typeof opts !== "object" || opts === null) return {};
  return opts as QROptions;
}

// ============================================================================
// Module Handlers
// ============================================================================

const qrGenerate: BuiltinHandler = (args) => {
  const text = String(args[0] ?? "");
  const opts = parseQROptions(args[1]);
  const ecLevel = opts.errorCorrectionLevel ?? "M";
  const matrix = generateQRMatrix(text, ecLevel);
  return matrixToDataUrl(matrix, { scale: opts.scale ?? 10, margin: opts.margin ?? 4 });
};

const qrToFile: BuiltinHandler = (args) => {
  const text = String(args[0] ?? "");
  const filePath = String(args[1] ?? "qr.svg");
  const opts = parseQROptions(args[2]);
  const ecLevel = opts.errorCorrectionLevel ?? "M";
  const matrix = generateQRMatrix(text, ecLevel);
  const svgWidth = opts.width ?? (matrix.length + (opts.margin ?? 4) * 2) * (opts.scale ?? 10);
  const svg = matrixToSvg(matrix, {
    width: svgWidth,
    margin: opts.margin ?? 4,
    darkColor: opts.color?.dark ?? "#000000",
    lightColor: opts.color?.light ?? "#ffffff",
  });
  writeFileSync(filePath, svg, "utf-8");
  return filePath;
};

const qrToSvg: BuiltinHandler = (args) => {
  const text = String(args[0] ?? "");
  const opts = parseQROptions(args[1]);
  const ecLevel = opts.errorCorrectionLevel ?? "M";
  const matrix = generateQRMatrix(text, ecLevel);
  return matrixToSvg(matrix, {
    margin: opts.margin ?? 4,
    darkColor: opts.color?.dark ?? "#000000",
    lightColor: opts.color?.light ?? "#ffffff",
  });
};

const qrToTerminal: BuiltinHandler = (args) => {
  const text = String(args[0] ?? "");
  const matrix = generateQRMatrix(text, "M");
  return matrixToTerminal(matrix);
};

// ============================================================================
// Barcode validation functions (pure JS, unchanged)
// ============================================================================

function ean13Check(digits: string): number {
  let sum = 0;
  for (let i = 0; i < 12; i++) sum += Number(digits[i]) * (i % 2 === 0 ? 1 : 3);
  return (10 - (sum % 10)) % 10;
}

const ean13Validate: BuiltinHandler = (args) => {
  const code = String(args[0] ?? "").replace(/\D/g, "");
  if (code.length !== 13) return false;
  return ean13Check(code) === Number(code[12]);
};

const ean13Checksum: BuiltinHandler = (args) => {
  const code = String(args[0] ?? "").replace(/\D/g, "");
  if (code.length < 12) return null;
  return String(ean13Check(code));
};

const upcValidate: BuiltinHandler = (args) => {
  const code = String(args[0] ?? "").replace(/\D/g, "");
  if (code.length !== 12) return false;
  return ean13Check("0" + code) === Number(code[11]);
};

const upcChecksum: BuiltinHandler = (args) => {
  const code = String(args[0] ?? "").replace(/\D/g, "");
  if (code.length < 11) return null;
  return String(ean13Check("0" + code));
};

const isbn10Validate: BuiltinHandler = (args) => {
  const isbn = String(args[0] ?? "").replace(/[-\s]/g, "");
  if (isbn.length !== 10) return false;
  let sum = 0;
  for (let i = 0; i < 10; i++) {
    const c = isbn[i]!;
    const val = c === "X" || c === "x" ? 10 : Number(c);
    if (isNaN(val)) return false;
    sum += val * (10 - i);
  }
  return sum % 11 === 0;
};

const isbn13Validate: BuiltinHandler = (args) => ean13Validate(args);

const isbn10to13: BuiltinHandler = (args) => {
  const isbn = String(args[0] ?? "").replace(/[-\s]/g, "");
  if (isbn.length !== 10) return null;
  const base = "978" + isbn.substring(0, 9);
  return base + String(ean13Check(base));
};

const isbn13to10: BuiltinHandler = (args) => {
  const isbn = String(args[0] ?? "").replace(/[-\s]/g, "");
  if (isbn.length !== 13 || !isbn.startsWith("978")) return null;
  const base = isbn.substring(3, 12);
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += Number(base[i]) * (10 - i);
  const check = (11 - (sum % 11)) % 11;
  return base + (check === 10 ? "X" : String(check));
};

const luhn: BuiltinHandler = (args) => {
  const num = String(args[0] ?? "").replace(/\D/g, "");
  let sum = 0;
  let alt = false;
  for (let i = num.length - 1; i >= 0; i--) {
    let n = Number(num[i]);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
};

const luhnGenerate: BuiltinHandler = (args) => {
  const num = String(args[0] ?? "").replace(/\D/g, "");
  for (let d = 0; d <= 9; d++) {
    if (luhn([num + String(d)]) === true) return num + String(d);
  }
  return num + "0";
};

// ============================================================================
// Exports
// ============================================================================

export const BarcodeFunctions: Record<string, BuiltinHandler> = { qrGenerate, qrToFile, qrToSvg, qrToTerminal, ean13Validate, ean13Checksum, upcValidate, upcChecksum, isbn10Validate, isbn13Validate, isbn10to13, isbn13to10, luhn, luhnGenerate };

export const BarcodeFunctionMetadata = {
  qrGenerate: { description: "Generate QR code as data URL", parameters: [{ name: "text", dataType: "string", description: "Text to encode", formInputType: "text", required: true }, { name: "options", dataType: "object", description: "{width, margin, scale, errorCorrectionLevel, color}", formInputType: "text", required: false }], returnType: "string", returnDescription: "Data URL (base64 PNG)", example: 'barcode.qrGenerate "https://example.com"' },
  qrToFile: { description: "Generate QR code to SVG file", parameters: [{ name: "text", dataType: "string", description: "Text", formInputType: "text", required: true }, { name: "filePath", dataType: "string", description: "Output path", formInputType: "text", required: true }, { name: "options", dataType: "object", description: "QR options", formInputType: "text", required: false }], returnType: "string", returnDescription: "File path", example: 'barcode.qrToFile "https://example.com" "./qr.svg"' },
  qrToSvg: { description: "Generate QR code as SVG", parameters: [{ name: "text", dataType: "string", description: "Text", formInputType: "text", required: true }], returnType: "string", returnDescription: "SVG string", example: 'barcode.qrToSvg "hello"' },
  qrToTerminal: { description: "Generate QR for terminal", parameters: [{ name: "text", dataType: "string", description: "Text", formInputType: "text", required: true }], returnType: "string", returnDescription: "Terminal string", example: 'barcode.qrToTerminal "hello"' },
  ean13Validate: { description: "Validate EAN-13 barcode", parameters: [{ name: "code", dataType: "string", description: "13-digit code", formInputType: "text", required: true }], returnType: "boolean", returnDescription: "true if valid", example: 'barcode.ean13Validate "4006381333931"' },
  ean13Checksum: { description: "Calculate EAN-13 check digit", parameters: [{ name: "code", dataType: "string", description: "12-digit code", formInputType: "text", required: true }], returnType: "string", returnDescription: "Check digit", example: 'barcode.ean13Checksum "400638133393"' },
  upcValidate: { description: "Validate UPC-A barcode", parameters: [{ name: "code", dataType: "string", description: "12-digit code", formInputType: "text", required: true }], returnType: "boolean", returnDescription: "true if valid", example: 'barcode.upcValidate "012345678905"' },
  upcChecksum: { description: "Calculate UPC-A check digit", parameters: [{ name: "code", dataType: "string", description: "11-digit code", formInputType: "text", required: true }], returnType: "string", returnDescription: "Check digit", example: 'barcode.upcChecksum "01234567890"' },
  isbn10Validate: { description: "Validate ISBN-10", parameters: [{ name: "isbn", dataType: "string", description: "ISBN-10", formInputType: "text", required: true }], returnType: "boolean", returnDescription: "true if valid", example: 'barcode.isbn10Validate "0-306-40615-2"' },
  isbn13Validate: { description: "Validate ISBN-13", parameters: [{ name: "isbn", dataType: "string", description: "ISBN-13", formInputType: "text", required: true }], returnType: "boolean", returnDescription: "true if valid", example: 'barcode.isbn13Validate "978-0-306-40615-7"' },
  isbn10to13: { description: "Convert ISBN-10 to ISBN-13", parameters: [{ name: "isbn10", dataType: "string", description: "ISBN-10", formInputType: "text", required: true }], returnType: "string", returnDescription: "ISBN-13", example: 'barcode.isbn10to13 "0306406152"' },
  isbn13to10: { description: "Convert ISBN-13 to ISBN-10", parameters: [{ name: "isbn13", dataType: "string", description: "ISBN-13", formInputType: "text", required: true }], returnType: "string", returnDescription: "ISBN-10 or null", example: 'barcode.isbn13to10 "9780306406157"' },
  luhn: { description: "Validate Luhn checksum", parameters: [{ name: "number", dataType: "string", description: "Number string", formInputType: "text", required: true }], returnType: "boolean", returnDescription: "true if valid", example: 'barcode.luhn "4539578763621486"' },
  luhnGenerate: { description: "Generate Luhn check digit", parameters: [{ name: "number", dataType: "string", description: "Number without check digit", formInputType: "text", required: true }], returnType: "string", returnDescription: "Number with check digit", example: 'barcode.luhnGenerate "453957876362148"' },
};

export const BarcodeModuleMetadata = {
  description: "QR code generation, EAN/UPC barcode validation, ISBN conversion, and Luhn checksum",
  methods: ["qrGenerate", "qrToFile", "qrToSvg", "qrToTerminal", "ean13Validate", "ean13Checksum", "upcValidate", "upcChecksum", "isbn10Validate", "isbn13Validate", "isbn10to13", "isbn13to10", "luhn", "luhnGenerate"],
};
