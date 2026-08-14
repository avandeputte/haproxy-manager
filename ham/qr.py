"""A QR code encoder, just large enough for an otpauth:// URI.

Written out here rather than imported because the app has no dependencies
beyond Flask, requests and waitress, and a QR library would be the first --
for one code, shown once, at enrolment. Byte mode, error-correction level M,
versions 1 to 10, which comfortably holds any otpauth URI this app produces.
The tests compare every module of the output against an independent encoder.
"""

# Reed-Solomon over GF(256) with the QR polynomial 0x11d.
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11d
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _poly_mul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if not x:
            continue
        for j, y in enumerate(b):
            if y:
                out[i + j] ^= _EXP[(_LOG[x] + _LOG[y]) % 255]
    return out


def _rs_remainder(data, degree):
    """The error-correction codewords for one block: the remainder of the
    message polynomial divided by the generator, both over GF(256)."""
    gen = [1]
    for i in range(degree):
        gen = _poly_mul(gen, [1, _EXP[i]])
    msg = list(data) + [0] * degree
    for i in range(len(data)):
        coef = msg[i]
        if coef:
            for j in range(1, len(gen)):
                if gen[j]:
                    msg[i + j] ^= _EXP[(_LOG[gen[j]] + _LOG[coef]) % 255]
    return msg[len(data):]


# Per version at level M: total data codewords, EC codewords per block, and
# the block structure as (count, data codewords per block) pairs.
_VERSIONS = {
    1:  (16, 10, [(1, 16)]),
    2:  (28, 16, [(1, 28)]),
    3:  (44, 26, [(1, 44)]),
    4:  (64, 18, [(2, 32)]),
    5:  (86, 24, [(2, 43)]),
    6:  (108, 16, [(4, 27)]),
    7:  (124, 18, [(4, 31)]),
    8:  (154, 22, [(2, 38), (2, 39)]),
    9:  (182, 22, [(3, 36), (2, 37)]),
    10: (216, 26, [(4, 43), (1, 44)]),
}
_ALIGN = {2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
          7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]}


def _choose_version(nbytes):
    for v, (cap, _ec, _blocks) in _VERSIONS.items():
        # byte mode header: 4 bits mode + 8 or 16 bits length
        overhead = 2 if v < 10 else 3
        if nbytes + overhead <= cap:
            return v
    raise ValueError("too long for a QR code this encoder makes (%d bytes)" % nbytes)


def _bits_to_codewords(data, version):
    cap, _ec, _blocks = _VERSIONS[version]
    bits = []

    def put(value, count):
        for i in range(count - 1, -1, -1):
            bits.append((value >> i) & 1)

    put(0b0100, 4)                       # byte mode
    put(len(data), 16 if version >= 10 else 8)
    for byte in data:
        put(byte, 8)
    put(0, min(4, cap * 8 - len(bits)))  # terminator
    while len(bits) % 8:
        bits.append(0)
    words = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad, i = (0xec, 0x11), 0
    while len(words) < cap:
        words.append(pad[i % 2])
        i += 1
    return words


def _interleave(words, version):
    _cap, ec, blocks = _VERSIONS[version]
    data_blocks, ec_blocks, k = [], [], 0
    for count, size in blocks:
        for _ in range(count):
            block = words[k:k + size]
            k += size
            data_blocks.append(block)
            ec_blocks.append(_rs_remainder(block, ec))
    out = []
    for i in range(max(len(b) for b in data_blocks)):
        for b in data_blocks:
            if i < len(b):
                out.append(b[i])
    for i in range(ec):
        for b in ec_blocks:
            out.append(b[i])
    return out


def _make_grid(version):
    """The fixed patterns, and a map of which modules are reserved."""
    size = 17 + 4 * version
    grid = [[0] * size for _ in range(size)]
    used = [[False] * size for _ in range(size)]

    def finder(r, c):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                rr, cc = r + dr, c + dc
                if 0 <= rr < size and 0 <= cc < size:
                    inside = 0 <= dr <= 6 and 0 <= dc <= 6
                    ring = inside and (dr in (0, 6) or dc in (0, 6) or (2 <= dr <= 4 and 2 <= dc <= 4))
                    grid[rr][cc] = 1 if ring else 0
                    used[rr][cc] = True

    finder(0, 0)
    finder(0, size - 7)
    finder(size - 7, 0)
    for i in range(8, size - 8):         # timing patterns
        grid[6][i] = grid[i][6] = (i + 1) % 2
        used[6][i] = used[i][6] = True
    coords = _ALIGN.get(version, [])
    for r in coords:
        for c in coords:
            # The three corners that would sit on a finder are left out; the
            # ones on the timing lines are NOT -- their pattern coincides with
            # the timing marks by design, and treating them as data (which
            # checking used[r][c] did, because timing had claimed the centre)
            # shifted every bit placed after them.
            if (r, c) in ((6, 6), (6, coords[-1]), (coords[-1], 6)):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    grid[r + dr][c + dc] = 1 if max(abs(dr), abs(dc)) != 1 else 0
                    used[r + dr][c + dc] = True
    grid[size - 8][8] = 1                # the dark module
    used[size - 8][8] = True
    # format information areas, reserved now and written later
    for i in range(9):
        used[8][i] = used[i][8] = True
    for i in range(8):
        used[8][size - 1 - i] = used[size - 1 - i][8] = True
    if version >= 7:
        bits = _version_bits(version)
        for i in range(18):
            v = (bits >> i) & 1
            grid[i // 3][size - 11 + i % 3] = v
            grid[size - 11 + i % 3][i // 3] = v
            used[i // 3][size - 11 + i % 3] = True
            used[size - 11 + i % 3][i // 3] = True
    return grid, used


def _version_bits(version):
    """The 18-bit version information block, BCH(18,6) coded."""
    rem = version << 12
    g = 0b1111100100101
    for i in range(17, 11, -1):
        if rem >> i & 1:
            rem ^= g << (i - 12)
    return (version << 12) | rem


def _place(grid, used, codewords):
    size = len(grid)
    bits = [(w >> (7 - b)) & 1 for w in codewords for b in range(8)]
    idx = 0
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1                     # the vertical timing column is skipped whole
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for c in (col, col - 1):
                if not used[row][c]:
                    grid[row][c] = bits[idx] if idx < len(bits) else 0
                    idx += 1
        upward = not upward
        col -= 2


_MASKS = [
    lambda r, c: (r + c) % 2 == 0,
    lambda r, c: r % 2 == 0,
    lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
]


def _penalty(grid):
    size = len(grid)
    score = 0
    for lines in (grid, list(zip(*grid))):           # rows, then columns
        for line in lines:
            run, prev = 0, None
            for v in line:
                if v == prev:
                    run += 1
                else:
                    if run >= 5:
                        score += 3 + (run - 5)
                    run, prev = 1, v
            if run >= 5:
                score += 3 + (run - 5)
    for r in range(size - 1):
        for c in range(size - 1):
            if grid[r][c] == grid[r][c + 1] == grid[r + 1][c] == grid[r + 1][c + 1]:
                score += 3
    pat = (1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0)
    for lines in (grid, list(zip(*grid))):
        for line in lines:
            t = tuple(line)
            for i in range(size - 10):
                if t[i:i + 11] in (pat, pat[::-1]):
                    score += 40
    dark = sum(sum(line) for line in grid)
    score += (abs(dark * 100 // (size * size) - 50) // 5) * 10
    return score


def _format_bits(mask):
    fmt = (0b00 << 3) | mask             # level M is 00
    rem = fmt << 10
    g = 0b10100110111
    for i in range(14, 9, -1):
        if rem >> i & 1:
            rem ^= g << (i - 10)
    return ((fmt << 10) | rem) ^ 0b101010000010010


def _write_format(grid, mask):
    size = len(grid)
    bits = _format_bits(mask)
    for i in range(15):
        v = (bits >> (14 - i)) & 1
        # around the top-left finder
        if i < 6:
            grid[8][i] = v
        elif i == 6:
            grid[8][7] = v
        elif i == 7:
            grid[8][8] = v
        elif i == 8:
            grid[7][8] = v
        else:
            grid[14 - i][8] = v
        # split between the other two finders: seven bits down the left
        # column -- the eighth module there is the dark module, not format --
        # and eight along the bottom of row 8 on the right.
        if i < 7:
            grid[size - 1 - i][8] = v
        else:
            grid[8][size - 15 + i] = v


def encode(text):
    """The QR matrix for a string: a list of rows of 0/1. Level M, byte mode."""
    data = text.encode("utf-8")
    version = _choose_version(len(data))
    codewords = _interleave(_bits_to_codewords(data, version), version)
    base, used = _make_grid(version)
    _place(base, used, codewords)
    best, best_score = None, None
    for m, fn in enumerate(_MASKS):
        grid = [row[:] for row in base]
        size = len(grid)
        for r in range(size):
            for c in range(size):
                if not used[r][c] and fn(r, c):
                    grid[r][c] ^= 1
        _write_format(grid, m)
        score = _penalty(grid)
        if best_score is None or score < best_score:
            best, best_score = grid, score
    return best
