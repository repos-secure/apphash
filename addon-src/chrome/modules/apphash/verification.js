var EXPORTED_SYMBOLS = ["apphash_verify"];

/* 
    SHA256 hash functionality modified from jsCrypto, by Mike Hamburg, 2008.
    Public domain.
 */
function SHA256() {
  if (!this.k[0])
    this.precompute();
  this.initialize();
}

SHA256.prototype = {
  init:[], k:[],

  precompute: function() {
    var p=2,i=0,j;

    function frac(x) { return (x-Math.floor(x)) * 4294967296 | 0 }

    outer: for (;i<64;p++) {
      for (j=2;j*j<=p;j++)
	if (p % j == 0)
	  continue outer;

      if (i<8) this.init[i] = frac(Math.pow(p,1/2));
      this.k[i] = frac(Math.pow(p,1/3));
      i++;
    }
  },

  initialize:function() {
    this.h = this.init.slice(0);
    this.word_buffer   = [];
    this.bit_buffer    = 0;
    this.bits_buffered = 0; 
    this.length        = 0;
    this.length_upper  = 0;
  },

  // one cycle of SHA256
  block:function(words) {
    var w=words.slice(0),i,h=this.h,tmp,k=this.k;

    var h0=h[0],h1=h[1],h2=h[2],h3=h[3],h4=h[4],h5=h[5],h6=h[6],h7=h[7];

    for (i=0;i<64;i++) {
      if (i<16) {
	tmp=w[i];
      } else {
        var a=w[(i+1)&15], b=w[(i+14)&15];
        tmp=w[i&15]=((a>>>7^a>>>18^a>>>3^a<<25^a<<14) + (b>>>17^b>>>19^b>>>10^b<<15^b<<13) + w[i&15] + w[(i+9)&15]) | 0;
      }
      
      tmp += h7 + (h4>>>6^h4>>>11^h4>>>25^h4<<26^h4<<21^h4<<7) + (h6 ^ h4&(h5^h6)) + k[i];
      
      h7=h6; h6=h5; h5=h4;
      h4 = h3 + tmp | 0;

      h3=h2; h2=h1; h1=h0;

      h0 = (tmp + ((h1&h2)^(h3&(h1^h2))) + (h1>>>2^h1>>>13^h1>>>22^h1<<30^h1<<19^h1<<10)) | 0;
    }

    h[0]+=h0; h[1]+=h1; h[2]+=h2; h[3]+=h3;
    h[4]+=h4; h[5]+=h5; h[6]+=h6; h[7]+=h7;
  },

  update_word_big_endian:function(word) {
    var bb;
    if ((bb = this.bits_buffered)) {
      this.word_buffer.push(word>>>(32-bb) ^ this.bit_buffer);
      this.bit_buffer = word << bb;
    } else {
      this.word_buffer.push(word);
    }
    this.length += 32;
    if (this.length == 0) this.length_upper ++; // mmhm..
    if (this.word_buffer.length == 16) {
      this.block(this.word_buffer);
      this.word_buffer = [];
    }
  },

  update_words_big_endian: function(words) { 
    for (var i=0; i<words.length; i++) this.update_word_big_endian(words[i]);
  },

  update_byte:function(byte) {
    this.bit_buffer ^= (byte & 0xff) << (24 - (this.bits_buffered));
    this.bits_buffered += 8;
    if (this.bits_buffered == 32) {
      this.bits_buffered = 0; 
      this.update_word_big_endian(this.bit_buffer);
      this.bit_buffer = 0;
    }
  },

  finalize:function() {
    var i, wb = this.word_buffer;

    wb.push(this.bit_buffer ^ (0x1 << (31 - this.bits_buffered)));
    if ((wb.length + 2) & 15){
        for (i = (wb.length + 2) & 15; i<16; i++) {
          wb.push(0);
        }
    }
    
    wb.push(this.length_upper);
    wb.push(this.length + this.bits_buffered);

    this.block(wb.slice(0,16));
    if (wb.length > 16) {
      this.block(wb.slice(16));
    }

    var h = this.h;
    this.initialize();
    return h;
  }
}


bytesToWords = function(bytes, words) {
    var paddedBytes = bytes.slice();
    while (paddedBytes.length % 4 != 0) paddedBytes.push(0);
	var num_words = Math.floor(paddedBytes.length/4);
	for (var j=0; j < num_words; j++)
		words[j] = (
                        (paddedBytes[(j<<2)+3]) |
                        (paddedBytes[(j<<2)+2] << 8) |
                        (paddedBytes[(j<<2)+1] << 16) |
                        (paddedBytes[j<<2] << 24)
                    );
};


asciiToBytes = function(ascii, bytes) {
	var len = ascii.length;
	for (var i=0; i < len; i++)
		bytes[i] = ascii.charCodeAt(i);
};


hex = function(n) {
  var out = "",i,digits="0123456789abcdef";
  for (i=0; i<8; i++) {
    var digit = n&0xF;
    out = digits.substring(digit,digit+1) + out;
    n = n >>> 4;
  }
  return out;
}

hexall = function(nn) {
  var out = "",i;
  for (i=0;i<nn.length;i++)
       out += hex(nn[i]);
  return out;
}

/*  Returns a hex representation of the SHA256 hash. */
SHA256.hash_string = function(s) {
    var bytes = [];
    var words = [];
    asciiToBytes(s, bytes);
    bytesToWords(bytes.slice(0, bytes.length-bytes.length%4), words);

    var s = new SHA256();
    for (var i=0; i<=words.length-16; i+=16) {
        s.block(words.slice(i,i+16));
    }
    s.length = i << 5; 
    if (i<words.length) {
        s.update_words_big_endian(words.slice(i));
    }
    for (var i=(bytes.length-bytes.length%4); i < bytes.length; i++){
        s.update_byte(bytes[i])
    }
    return hexall(s.finalize());
}


/* 
 * Returns an object with keys "base" and "hostile".
 */
function apphash_split(s){
    var marker = "// APPHASH_HOSTILE_ZONE";
    var start = s.indexOf(marker);
    var end = s.lastIndexOf(marker);
    if (start < 0 || end < 0 || start == end)
        return {
            "base": s,
            "hostile": null
        }
    else
        return {
            "base": s.slice(0, start) + s.slice(end+marker.length),
            "hostile": s.slice(start+marker.length, end)
        }
}


const ASSIGNMENT_RE = /^\s*var\s+\w+\s+=\s+"(.*[^\\])?";\s*$/;
function apphash_hostile_check(hb){
    var lines = hb.split(/\n|\r/);
    for (var i=0; i < lines.length; i++){
        if (!lines[i].match(/^\s*$/)){
            var rex = lines[i].match(ASSIGNMENT_RE);
            if (!rex) {
                return "non-assignment line in hostile block";
            }
            /* If this is false, we have an empty string assignment. */
            if (rex[1]){
                /* First, we strike the double-slashes */
                var s = rex[1].replace(/\\\\/g, "");
                /* Now, if there's a quote or angle bracket not preceded by a slash, we fail */
                if (s.match(/[^\\]["'<>]/))
                    return "unescaped special character in string assignment";
                /* ... and if there's a slash not followed by a special char, we fail */
                if (s.match(/\\[^"'nr<>]/)){
                    return "hanging backslash in string assignment"
                }
            }
        }
    }
    return null;
}



/* 
  This is the business end of the verification process. The page is divided
  into two parts: a static zone, that is checked against a hash, and a hostile
  zone, that is constrained to a set of string assignments of the following
  form:
 
   var name = "string";
 
  Vaid strings are bytes with ordinal values 0-255, except that \n, \r, \, '
  and " must be backslash escaped.

  Returns a string error on failure, and "ok" on success.
*/
function apphash_verify(s, hash){
    var hashcontent = null;
    var parts = apphash_split(s);
    if (parts.hostile != null){
        var check = apphash_hostile_check(parts.hostile);
        if (check)
            return check
    }
    var thishash = SHA256.hash_string(parts.base);
    if (thishash == hash)
        return "ok";
    else
        return thishash;
}

