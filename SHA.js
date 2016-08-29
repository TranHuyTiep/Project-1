/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.

 */

; (function (root) {
    var HEX_CHARS = '0123456789abcdef'.split('');
    var PADDING = [6, 1536, 393216, 100663296];             
    var SHIFT = [0, 8, 16, 24];
    var RC = [1, 0, 32898, 0, 32906, 2147483648, 2147516416, 2147483648, 32907, 0, 2147483649,
              0, 2147516545, 2147483648, 32777, 2147483648, 138, 0, 136, 0, 2147516425, 0,
              2147483658, 0, 2147516555, 0, 139, 2147483648, 32905, 2147483648, 32771,
              2147483648, 32770, 2147483648, 128, 2147483648, 32778, 0, 2147483658, 2147483648,
              2147516545, 2147483648, 32896, 2147483648, 2147483649, 0, 2147516424, 2147483648];
    var BITS = [224, 256, 384, 512];
    var OUTPUT_TYPES = 'hex';
    var createOutputMethod = function (bits, padding, outputType) {                             //  
        return function (message) {
            return new Keccak(bits, padding, bits).update(message)[outputType]();
        }
    };
    var createMethod = function (bits, padding) {
        var method = createOutputMethod(bits, padding, 'hex');
        method.create = function () {
            return new Keccak(bits, padding, bits);
        };
        method.update = function (message) {                              
            return method.create().update(message);
        };
        var type = OUTPUT_TYPES;
        method[type] = createOutputMethod(bits, padding, type);
        return method;
    };
    var algorithms = {padding: PADDING, bits: BITS, createMethod: createMethod };
    var methods = [];
        var algorithm = algorithms;
        var bits = algorithm.bits;
        var createMethod = algorithm.createMethod;
        for (var j = 0; j < bits.length; ++j) {
            var method = algorithm.createMethod(bits[j], algorithm.padding);
            methods['SHA3_' + bits[j]] = method;
    }

    function Keccak(bits, padding, outputBits) {
        this.blocks = [];  
        this.s = [];       
        this.padding = padding;
        this.outputBits = outputBits;   
        this.reset = true;
        this.block = 0;
        this.start = 0;
        this.blockCount = (1600 - (bits << 1)) >> 5;       
        this.byteCount = this.blockCount << 2;              
        this.outputBlocks = outputBits >> 5;                    
        for (var i = 0; i < 50; ++i) {
            this.s[i] = 0;
        }
    };

    Keccak.prototype.update = function (message) {
        var notString = typeof (message) != 'string';
        if (notString) {
            message = '';
        }
        var length = message.length, blocks = this.blocks, byteCount = this.byteCount,
            blockCount = this.blockCount, index = 0, s = this.s, i, code;

        while (index < length) {
            if (this.reset) {
                this.reset = false;
                blocks[0] = this.block;
                for (i = 1; i < blockCount + 1; ++i) {
                    blocks[i] = 0;
                }
            }
            if (notString) {
                for (i = this.start; index < length && i < byteCount; ++index) {
                    blocks[i >> 2] |= message[index] << SHIFT[i++ & 3];
                }
            } 
            else {
            for (i = this.start; index < length && i < byteCount; ++index) {                           
                code = message.charCodeAt(index);
                if (code < 0x80) {
                    blocks[i >> 2] |= code << SHIFT[i++ & 3];
                }
                    else if (code < 0x7FF) {
                        blocks[i >> 2] |= (0xc0 | (code >> 6)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                    }
                    else if (code < 0xFFFF || code >= 0x800) {
                        blocks[i >> 2] |= (0xe0 | (code >> 12)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                    }else {
                        code = 0x10000 + (((code & 0x3ff) << 10) | (message.charCodeAt(++index) & 0x3ff));
                        blocks[i >> 2] |= (0xf0 | (code >> 18)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | ((code >> 12) & 0x3f)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                    }
                }
            }
            this.lastByteIndex = i;
            if (i >= byteCount) {                               
                this.start = i - byteCount;
                this.block = blocks[blockCount];
                for (j = 0; j < blockCount; ++j) {
                    s[j] ^= blocks[j];
                }
                f(s);
                this.reset = true;
            } else {
                this.start = i;
            }
        }
        return this;
    };

    Keccak.prototype.finalize = function () {                               
        var blocks = this.blocks, i = this.start, blockCount = this.blockCount, s = this.s;
        blocks[i >> 2] |= this.padding[i & 3];                              
        blocks[blockCount - 1] |= 0x80000000;                                                
        for (i = 0; i < blockCount; ++i) {                                  
            s[i] ^= blocks[i];
        }
        f(s);                                                              
    };

     Keccak.prototype.hex = function () {        
        this.finalize();
        var blockCount = this.blockCount, s = this.s, outputBlocks = this.outputBlocks,i = 0, j = 0;
        var hex = '', block;
        while (j < outputBlocks) {
            for (i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
                block = s[i];
                hex += HEX_CHARS[(block >> 4  ) & 0xF] + HEX_CHARS[block & 0xF] +
                       HEX_CHARS[(block >> 12) & 0xF] + HEX_CHARS[(block >> 8) & 0xF] +
                       HEX_CHARS[(block >> 20) & 0xF] + HEX_CHARS[(block >> 16) & 0xF] +
                       HEX_CHARS[(block >> 28) & 0xF] + HEX_CHARS[(block >> 24) & 0xF];
            }
              if (j % blockCount == 0) {
                f(s);
            }
        }
        return hex;
    };
    var f = function (s) {
        var h, l, n,c=[],b=[];
        for (n = 0; n < 48; n += 2) {
            // theta
            // C[x] = A[x,0]⊕A[x,1]⊕A[x,2]⊕A[x,3]⊕A[x,4] 
            c[0] = s[0] ^ s[10] ^ s[20] ^ s[30] ^ s[40];
            c[1] = s[1] ^ s[11] ^ s[21] ^ s[31] ^ s[41];
            c[2] = s[2] ^ s[12] ^ s[22] ^ s[32] ^ s[42];
            c[3] = s[3] ^ s[13] ^ s[23] ^ s[33] ^ s[43];
            c[4] = s[4] ^ s[14] ^ s[24] ^ s[34] ^ s[44];
            c[5] = s[5] ^ s[15] ^ s[25] ^ s[35] ^ s[45];
            c[6] = s[6] ^ s[16] ^ s[26] ^ s[36] ^ s[46];
            c[7] = s[7] ^ s[17] ^ s[27] ^ s[37] ^ s[47];
            c[8] = s[8] ^ s[18] ^ s[28] ^ s[38] ^ s[48];
            c[9] = s[9] ^ s[19] ^ s[29] ^ s[39] ^ s[49]
//          D[x] = C[x−1]⊕rot(C[x+1],1) , x = 0,1,2,3,4
//          A[x, y] = A[x, y]⊕D[x]
            h = c[8] ^ ((c[2] << 1) | (c[3] >>> 31));
            l = c[9] ^ ((c[3] << 1) | (c[2] >>> 31));
            s[0] ^= h;
            s[1] ^= l;
            s[10] ^= h;
            s[11] ^= l;
            s[20] ^= h;
            s[21] ^= l;
            s[30] ^= h;
            s[31] ^= l;
            s[40] ^= h;
            s[41] ^= l;
            h = c[0] ^ ((c[4] << 1) | (c[5] >>> 31));
            l = c[1] ^ ((c[5] << 1) | (c[4] >>> 31));
            s[2] ^= h;
            s[3] ^= l;
            s[12] ^= h;
            s[13] ^= l;
            s[22] ^= h;
            s[23] ^= l;
            s[32] ^= h;
            s[33] ^= l;
            s[42] ^= h;
            s[43] ^= l;
            h = c[2] ^ ((c[6] << 1) | (c[7] >>> 31));
            l = c[3] ^ ((c[7] << 1) | (c[6] >>> 31));
            s[4] ^= h;
            s[5] ^= l;
            s[14] ^= h;
            s[15] ^= l;
            s[24] ^= h;
            s[25] ^= l;
            s[34] ^= h;
            s[35] ^= l;
            s[44] ^= h;
            s[45] ^= l;
            h = c[4] ^ ((c[8] << 1) | (c[9] >>> 31));
            l = c[5] ^ ((c[9] << 1) | (c[8] >>> 31));
            s[6] ^= h;
            s[7] ^= l;
            s[16] ^= h;
            s[17] ^= l;
            s[26] ^= h;
            s[27] ^= l;
            s[36] ^= h;
            s[37] ^= l;
            s[46] ^= h;
            s[47] ^= l;
            h = c[6] ^ ((c[0] << 1) | (c[1] >>> 31));
            l = c[7] ^ ((c[1] << 1) | (c[0] >>> 31));
            s[8] ^= h;
            s[9] ^= l;
            s[18] ^= h;
            s[19] ^= l;
            s[28] ^= h;
            s[29] ^= l;
            s[38] ^= h;
            s[39] ^= l;
            s[48] ^= h;
            s[49] ^= l;
            //// Rho Pi B[y,2x+3y] = rot(A[x,y],r[x, y]) 
            b[0] = s[0];
            b[1] = s[1];
            b[32] = (s[11] << 4) | (s[10] >>> 28);///32bit ,
            b[33] = (s[10] << 4) | (s[11] >>> 28);
            b[14] = (s[20] << 3) | (s[21] >>> 29);
            b[15] = (s[21] << 3) | (s[20] >>> 29);
            b[46] = (s[31] << 9) | (s[30] >>> 23);
            b[47] = (s[30] << 9) | (s[31] >>> 23);
            b[28] = (s[40] << 18) | (s[41] >>> 14);
            b[29] = (s[41] << 18) | (s[40] >>> 14);
            b[20] = (s[2] << 1) | (s[3] >>> 31);
            b[21] = (s[3] << 1) | (s[2] >>> 31);
            b[2] = (s[13] << 12) | (s[12] >>> 20);
            b[3] = (s[12] << 12) | (s[13] >>> 20);
            b[34] = (s[22] << 10) | (s[23] >>> 22);
            b[35] = (s[23] << 10) | (s[22] >>> 22);
            b[16] = (s[33] << 13) | (s[32] >>> 19);
            b[17] = (s[32] << 13) | (s[33] >>> 19);
            b[48] = (s[42] << 2) | (s[43] >>> 30);
            b[49] = (s[43] << 2) | (s[42] >>> 30);
            b[40] = (s[5] << 30) | (s[4] >>> 2);
            b[41] = (s[4] << 30) | (s[5] >>> 2);
            b[22] = (s[14] << 6) | (s[15] >>> 26);
            b[23] = (s[15] << 6) | (s[14] >>> 26);
            b[4] = (s[25] << 11) | (s[24] >>> 21);
            b[5] = (s[24] << 11) | (s[25] >>> 21);
            b[36] = (s[34] << 15) | (s[35] >>> 17);
            b[37] = (s[35] << 15) | (s[34] >>> 17);
            b[18] = (s[45] << 29) | (s[44] >>> 3);
            b[19] = (s[44] << 29) | (s[45] >>> 3);
            b[10] = (s[6] << 28) | (s[7] >>> 4);
            b[11] = (s[7] << 28) | (s[6] >>> 4);
            b[42] = (s[17] << 23) | (s[16] >>> 9);
            b[43] = (s[16] << 23) | (s[17] >>> 9);
            b[24] = (s[26] << 25) | (s[27] >>> 7);
            b[25] = (s[27] << 25) | (s[26] >>> 7);
            b[6] = (s[36] << 21) | (s[37] >>> 11);
            b[7] = (s[37] << 21) | (s[36] >>> 11);
            b[38] = (s[47] << 24) | (s[46] >>> 8);
            b[39] = (s[46] << 24) | (s[47] >>> 8);
            b[30] = (s[8] << 27) | (s[9] >>> 5);
            b[31] = (s[9] << 27) | (s[8] >>> 5);
            b[12] = (s[18] << 20) | (s[19] >>> 12);
            b[13] = (s[19] << 20) | (s[18] >>> 12);
            b[44] = (s[29] << 7) | (s[28] >>> 25);
            b[45] = (s[28] << 7) | (s[29] >>> 25);
            b[26] = (s[38] << 8) | (s[39] >>> 24);
            b[27] = (s[39] << 8) | (s[38] >>> 24);
            b[8] = (s[48] << 14) | (s[49] >>> 18);
            b[9] = (s[49] << 14) | (s[48] >>> 18);
      // // Chi A[x,y] = B[x, y]⊕((B¯[x+1, y])∧B[x+2,y]) 
            s[0] = b[0] ^ (~b[2] & b[4]);
            s[1] = b[1] ^ (~b[3] & b[5]);
            s[2] = b[2] ^ (~b[4] & b[6]);
            s[3] = b[3] ^ (~b[5] & b[7]);
            s[4] = b[4] ^ (~b[6] & b[8]);
            s[5] = b[5] ^ (~b[7] & b[9]);
            s[4] = b[4] ^ (~b[6] & b[8]);
            s[5] = b[5] ^ (~b[7] & b[9]);
            s[6] = b[6] ^ (~b[8] & b[0]);
            s[7] = b[7] ^ (~b[9] & b[1]);
            s[8] = b[8] ^ (~b[0]& b[2]);
            s[9] = b[9] ^ (~b[1] & b[3]);
            
            s[10] = b[10] ^ (~b[12] & b[14]);
            s[11] = b[11] ^ (~b[13] & b[15]);
            s[12] = b[12] ^ (~b[14] & b[16]);
            s[13] = b[13] ^ (~b[15] & b[17]);
            s[14] = b[14] ^ (~b[16] & b[18]);
            s[15] = b[15] ^ (~b[17] & b[19]);
            s[16] = b[16] ^ (~b[18] & b[10]);
            s[17] = b[17] ^ (~b[19] & b[11]);
            s[18] = b[18] ^ (~b[10] & b[12]);
            s[19] = b[19] ^ (~b[11] & b[13]);
            
            s[20] = b[20] ^ (~b[22] & b[24]);
            s[21] = b[21] ^ (~b[23] & b[25]);
            s[22] = b[22] ^ (~b[24] & b[26]);
            s[23] = b[23] ^ (~b[25] & b[27]);
            s[24] = b[24] ^ (~b[26 ]& b[28]);
            s[25] = b[25] ^ (~b[27 ]& b[29]);
            s[26] = b[26] ^ (~b[28] & b[20]);
            s[27] = b[27] ^ (~b[29] & b[21]);
            s[28] = b[28] ^ (~b[20] & b[22]);
            s[29] = b[29] ^ (~b[21] & b[23]);
            
            s[30] = b[30] ^ (~b[32] & b[34]);
            s[31] = b[31] ^ (~b[33] & b[35]);
            s[32] = b[32] ^ (~b[34] & b[36]);
            s[33] = b[33] ^ (~b[35] & b[37]);
            s[34] = b[34] ^ (~b[36] & b[38]);
            s[35] = b[35] ^ (~b[37] & b[39]);
            s[36] = b[36] ^ (~b[38] & b[30]);
            s[37] = b[37] ^ (~b[39] & b[31]);
            s[38] = b[38] ^ (~b[30] & b[32]);
            s[39] = b[39] ^ (~b[31] & b[33]);
            s[40] = b[40] ^ (~b[42] & b[44]);
            s[41] = b[41] ^ (~b[43 ]& b[45]);
            
            s[42] = b[42] ^ (~b[44] & b[46]);
            s[43] = b[43] ^ (~b[45] & b[47]);
            s[44] = b[44] ^ (~b[46] & b[48]);
            s[45] = b[45] ^ (~b[47] & b[49]);
            s[46] = b[46] ^ (~b[48] & b[40]);
            s[47] = b[47] ^ (~b[49] & b[41]);
            s[48] = b[48] ^ (~b[40 ]& b[42]);
            s[49] = b[49] ^ (~b[41] & b[43]);
            //// Iota A[0,0] = A[0,0]⊕RC[i]
            s[0] ^= RC[n];
            s[1] ^= RC[n + 1];
        }
    }
        for (var key in methods) {
            root[key] = methods[key];
        }
    
}(this));

