function hexDump(buf) {
  var len = buf.length;
  if (typeof(buf) == "string") {
    var tmp = buf.split('');
    buf = new Uint8Array(len);
    for(i = 0; i < len; i++) {
      buf[i] = tmp[i].charCodeAt(0);
    }
  }
  var i, j, alphabet = "0123456789abcdef";
  alphabet = alphabet.split('');
  console.log("     +------------------------------------------------+ +----------------+");
  console.log("     |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |");
  for (i = 0; i < len; i += 16) {
    if (i % 128 == 0)
      console.log("     +------------------------------------------------+ +----------------+");
    var s = "|                                                | |                |";
    s = s.split('');
    var ix = 1, iy = 52;
    for (j = 0; j < 16; j++) {
      if (i + j < len) {
        var c = buf[i + j];
        s[ix++] = alphabet[(c >> 4) & 0x0F];
        s[ix++] = alphabet[c & 0x0F];
        ix++;
        if (c > 31 && c < 128) s[iy++] = String.fromCharCode(c);
        else s[iy++] = '.';
      }
    }
    var index = i / 16;
    v = index.toString(); while(v.length<3) v = '0'+v;
    v +='.';
    console.log(v, s.join(''));
  }
  console.log("     +------------------------------------------------+ +----------------+");
}


var AES_TYPE = 128;
// var AES_TYPE = 192;
// var AES_TYPE = 256;
var AES_BLOCKLEN = 16;
var AES_KEYLEN = AES_TYPE / 8;
var AES_keyExpSize = 176; // AES 128
if (AES_KEYLEN == 32) AES_keyExpSize = 240;
else if (AES_KEYLEN == 24) AES_keyExpSize = 208;

var AES_ctx = {};
AES_ctx.RoundKey = new Uint8Array(AES_keyExpSize);
AES_ctx.Iv = new Uint8Array(AES_BLOCKLEN);

var Nb = 4;
var Nk = 4; // AES 128 The number of 32 bit words in a key.
var Nr = 10; // The number of rounds in AES Cipher.

if (AES_KEYLEN == 32) {
  Nk = 8; // AES 128 The number of 32 bit words in a key.
  Nr = 14; // The number of rounds in AES Cipher.
} else if (AES_KEYLEN == 24) {
  Nk = 6; // AES 128 The number of 32 bit words in a key.
  Nr = 12; // The number of rounds in AES Cipher.
}

var sbox = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]);
var rsbox = new Uint8Array([
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]);
var Rcon = new Uint8Array([
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]);

function getSBoxValue(num) {
  return sbox[(num)];
}
function getSBoxInvert(num) {
  return rsbox[(num)];
}

function KeyExpansion(Key) {
  var i, j, k;
  if (typeof(Key) == "string") {
    console.log("String key");
    var keyLen = Key.length;
    if (keyLen != AES_KEYLEN) {
      console.log("Invalid key length:", keyLen);
      return;
    }
    var tmp = Key.split('');
    Key = new Uint8Array(AES_KEYLEN);
    for(i = 0; i < AES_KEYLEN; i++) {
      Key[i] = tmp[i].charCodeAt(0);
    }
  }
  tempa = new Uint8Array(4); // Used for the column/row operations
  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i) {
    AES_ctx.RoundKey[(i * 4)] = Key[(i * 4)];
    AES_ctx.RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    AES_ctx.RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    AES_ctx.RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }
  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i) {
    {
      k = (i - 1) * 4;
      tempa[0] = AES_ctx.RoundKey[k];
      tempa[1] = AES_ctx.RoundKey[k + 1];
      tempa[2] = AES_ctx.RoundKey[k + 2];
      tempa[3] = AES_ctx.RoundKey[k + 3];
    }
    if (i % Nk == 0) {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
      // Function RotWord().
      {
        var u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }
      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.
      // Function Subword().
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
      tempa[0] = tempa[0] ^ Rcon[i / Nk];
    }
    if (AES_TYPE = 256) {
      if (i % Nk == 4) {
        // Function Subword().
        {
          tempa[0] = getSBoxValue(tempa[0]);
          tempa[1] = getSBoxValue(tempa[1]);
          tempa[2] = getSBoxValue(tempa[2]);
          tempa[3] = getSBoxValue(tempa[3]);
        }
      }
    }
    j = i * 4; k = (i - Nk) * 4;
    AES_ctx.RoundKey[j] = AES_ctx.RoundKey[k] ^ tempa[0];
    AES_ctx.RoundKey[j + 1] = AES_ctx.RoundKey[k + 1] ^ tempa[1];
    AES_ctx.RoundKey[j + 2] = AES_ctx.RoundKey[k + 2] ^ tempa[2];
    AES_ctx.RoundKey[j + 3] = AES_ctx.RoundKey[k + 3] ^ tempa[3];
  }
}

function AES_init_ctx(key) {
  KeyExpansion(key);
}
function AES_init_ctx_iv(key, iv) {
  KeyExpansion(key);
  for(i = 0; i < AES_BLOCKLEN; i++) AES_ctx.Iv[i] = iv[i];
}
function AES_ctx_set_iv(iv) {
  for(i = 0; i < AES_BLOCKLEN; i++) AES_ctx.Iv[i] = iv[i];
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
function AddRoundKey(round, state) {
  var i, j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      state[i*4+j] ^= AES_ctx.RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
  return state;
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
function SubBytes(state) {
  var i, j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      state[j*4+i] = getSBoxValue(state[j*4+i]);
    }
  }
  return state;
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
function ShiftRows(state) {
  // Rotate first row 1 columns to left
  var temp = state[1];
  state[1] = state[1*4+1];
  state[1*4+1] = state[2*4+1];
  state[2*4+1] = state[3*4+1];
  state[3*4+1] = temp;
  // Rotate second row 2 columns to left
  temp = state[2];
  state[2] = state[2*4+2];
  state[2*4+2] = temp;
  temp = state[1*4+2];
  state[1*4+2] = state[3*4+2];
  state[3*4+2] = temp;
  // Rotate third row 3 columns to left
  temp = state[3];
  state[3] = state[3*4+3];
  state[3*4+3] = state[2*4+3];
  state[2*4+3] = state[1*4+3];
  state[1*4+3] = temp;
  return state;
}

function xtime(x) {
  return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
function MixColumns(state) {
  var i;
  var Tmp, Tm, t;
  for (i = 0; i < 4; ++i) {
    t   = state[i*4];
    Tmp = state[i*4] ^ state[i*4+1] ^ state[i*4+2] ^ state[i*4+3] ;
    Tm  = state[i*4] ^ state[i*4+1] ; Tm = xtime(Tm);  state[i*4] ^= Tm ^ Tmp ;
    Tm  = state[i*4+1] ^ state[i*4+2] ; Tm = xtime(Tm);  state[i*4+1] ^= Tm ^ Tmp ;
    Tm  = state[i*4+2] ^ state[i*4+3] ; Tm = xtime(Tm);  state[i*4+2] ^= Tm ^ Tmp ;
    Tm  = state[i*4+3] ^ t ; Tm = xtime(Tm);  state[i*4+3] ^= Tm ^ Tmp ;
  }
  return state;
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
// The compiler seems to be able to vectorize the operation better this way.
function Multiply(x, y) {
  return (((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^ ((y >> 2 & 1) * xtime(xtime(x))) ^ ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^ ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
  /* this last call to xtime() can be omitted */
}

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
function InvMixColumns(state) {
  var i, a, b, c, d;
  for (i = 0; i < 4; ++i) {
    a = state[i*4];
    b = state[i*4+1];
    c = state[i*4+2];
    d = state[i*4+3];
    state[i*4] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    state[i*4+1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    state[i*4+2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    state[i*4+3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
function InvSubBytes(state) {
  var i, j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      state[j*4+i] = getSBoxInvert(state[j*4+i]);
    }
  }
}

function InvShiftRows(state) {
  var temp;
  // Rotate first row 1 columns to right
  temp = state[3*4+1];
  state[3*4+1] = state[2*4+1];
  state[2*4+1] = state[1*4+1];
  state[1*4+1] = state[1];
  state[1] = temp;
  // Rotate second row 2 columns to right
  temp = state[2];
  state[2] = state[2*4+2];
  state[2*4+2] = temp;
  temp = state[1*4+2];
  state[1*4+2] = state[3*4+2];
  state[3*4+2] = temp;
  // Rotate third row 3 columns to right
  temp = state[3];
  state[3] = state[1*4+3];
  state[1*4+3] = state[2*4+3];
  state[2*4+3] = state[3*4+3];
  state[3*4+3] = temp;
}

// Cipher is the main function that encrypts the plaintext.
function Cipher(state) {
  var round = 0;
  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, AES_ctx.RoundKey);
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without MixColumns().
  for (round = 1; ; ++round) {
    SubBytes(state);
    ShiftRows(state);
    if (round == Nr) break;
    MixColumns(state);
    AddRoundKey(round, state, AES_ctx.RoundKey);
  }
  // Add round key to last round
  AddRoundKey(Nr, state, AES_ctx.RoundKey);
}

function InvCipher(state) {
  var round = 0;
  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr, state, AES_ctx.RoundKey);
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without InvMixColumn().
  for (round = (Nr - 1); ; --round) {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, state, AES_ctx.RoundKey);
    if (round == 0) break;
    InvMixColumns(state);
  }
}

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
function state2msg(st) {
  var i, tmp = [], ln = st.length;
  for (i = 0; i < ln; i++) {
    if (st[i] == 0) break;
    tmp.push(String.fromCharCode(st[i]));
  }
  return tmp.join('');
}

function AdjustLength(buf) {
  var ln = buf.length + 1, olen = ln;
  if (ln < 16) olen = 16;
  else if (ln % 16 != 0) olen = ((ln >> 4) + 1) * 16;
  // console.log("ln:", ln, "olen:", olen);
  var diff = olen - ln;
  var state = new Uint8Array(olen);
  var tmp = buf.split('');
  var i, j;
  for (i = 0; i < ln-1; i++) state[i] = tmp[i].charCodeAt(0);
  state[i++] = 0;
  for(j = i; j < olen; j++) state[j] = diff;
  return [state, olen];
}

function AES_ECB_encrypt(buf, key) {
  // The next function call encrypts the PlainText with the Key using AES algorithm.
  AES_init_ctx(key);
  var state, olen;
  [state, olen] = AdjustLength(buf);
  var ttlLen = olen + AES_BLOCKLEN;
  var finalState = new Uint8Array(ttlLen);
  var i, j;
  for (j = 0; j < AES_BLOCKLEN; j++) finalState[j] = Math.random()*256;
  for (i = 0; i < olen; i += AES_BLOCKLEN)  {
    var myTemp = new Uint8Array(AES_BLOCKLEN);
    for (j = 0; j < AES_BLOCKLEN; j++) myTemp[j] = state[j+i];
    Cipher(myTemp);
    for (j = 0; j < AES_BLOCKLEN; j++) finalState[j+i+AES_BLOCKLEN] = myTemp[j];
  }
  return finalState;
}

function AES_ECB_decrypt(state, key) {
  // The next function call decrypts the PlainText with the Key using AES algorithm.
  AES_init_ctx(key);
  var i, j;
  if(typeof(state)=='string') {
    // base64 string
    // console.log("BASE64")
    var x=atob(state);
    x=x.split(',');
    j = x.length;
    state = new Uint8Array(j);
    for (i=0; i<j; i++) state[i] = parseInt(x[i]);
    hexDump(state);
  }
  var olen = state.length;
  var finalState = new Uint8Array(olen-16);
  for (i = 0; i < olen; i += AES_BLOCKLEN)  {
    var myTemp = new Uint8Array(AES_BLOCKLEN);
    for (j = 0; j < AES_BLOCKLEN; j++) myTemp[j] = state[j+i];
    InvCipher(myTemp);
    if (i > 0) {
      for (j = 0; j < AES_BLOCKLEN; j++) finalState[j+i-AES_BLOCKLEN] = myTemp[j];
    }
  }
  return finalState;
}

function XorWithIv(buf) {
  var i;
  for (i = 0; i < AES_BLOCKLEN; ++i) {
    // The block in AES is always 128 bits no matter the key size
    buf[i] ^= AES_ctx.Iv[i];
  }
}

function AES_CBC_encrypt_buffer(buf, key, myIV) {
  AES_init_ctx_iv(key, myIV);
  var state, olen;
  console.log("myIV,", btoa(myIV));
  [state, olen] = AdjustLength(buf);
  var ttlLen = olen + AES_BLOCKLEN;
  var finalState = new Uint8Array(ttlLen);
  var i, j;
  for (j = 0; j < AES_BLOCKLEN; j++) finalState[j] = Math.random()*256;
  for (j=0; j < olen; j++) finalState[j+AES_BLOCKLEN] = state[j];
  for (i = 0; i < ttlLen; i += AES_BLOCKLEN)  {
    var myTemp = new Uint8Array(AES_BLOCKLEN);
    for (j = 0; j < AES_BLOCKLEN; j++) myTemp[j] = finalState[j+i];
    XorWithIv(myTemp);
    Cipher(myTemp);
    for (j = 0; j < AES_BLOCKLEN; j++) {
      finalState[j+i] = myTemp[j];
      AES_ctx.Iv[j] = myTemp[j];
    }
  }
  return finalState;
}

// TBC
function AES_CBC_decrypt_buffer(buf, key, myIV) {
  AES_init_ctx_iv(key, myIV);
  var i, j, ln = buf.length;
  var finalState = new Uint8Array(ln - AES_BLOCKLEN);
  var storeNextIv = new Uint8Array(AES_BLOCKLEN);
  for (i = 0; i < ln; i += AES_BLOCKLEN) {
    var myTemp = new Uint8Array(AES_BLOCKLEN);
    for (j = 0; j < AES_BLOCKLEN; j++) {
      storeNextIv[j] = buf[j+i];
      myTemp[j] = buf[j+i];
    }
    InvCipher(myTemp);
    XorWithIv(myTemp);
    for (j = 0; j < AES_BLOCKLEN; j++) AES_ctx.Iv[j] = storeNextIv[j];
    if (i > 0) {
      for (j = 0; j < AES_BLOCKLEN; j++) {
        finalState[j+i-AES_BLOCKLEN] = myTemp[j];
      }
    }
  }
  return finalState;
}

function generate16bytes() {
  var truc = new Uint8Array(16);
  for (i=0; i<16; i++) {
    truc[i] = Math.random()*256;
  }
  return truc;
}

var key = generate16bytes();
var myIV = generate16bytes();

// var enc = AES_ECB_encrypt("Oh hello there! Let's try something something a bit longer. Like this.", key);
// console.log("Key");
// hexDump(key);
// console.log("myIV");
// hexDump(myIV);
// console.log("ECB Encrypted");
// hexDump(enc);
// b64 = btoa(enc);
// //console.log(b64);
// console.log("ECB Decrypting from Uint8Array");
// var dec = AES_ECB_decrypt(enc, key);
// hexDump(dec);
// console.log((state2msg(dec)));
// console.log("ECB Decrypting from Base64");
// console.log(b64);
// var dec = AES_ECB_decrypt(b64, key);
// hexDump(dec);
// console.log((state2msg(dec)));

var enc = AES_CBC_encrypt_buffer("Oh hello there! Let's try something something a bit longer. Like this.", key, myIV);
console.log("CBC Encrypted");
hexDump(enc);
var dec = AES_CBC_decrypt_buffer(enc, key, myIV);
console.log("CBC Decrypted");
hexDump(dec);
console.log((state2msg(dec)));
