#TRUSTED 4c4f2d748ff622f8e23d376b26e1d00c5c5de8dcdeed8e067fd4f4a8fb895aae9c195388e058a964825b4ca6437e734c27832425787300692aa8ec0a0beb72c1edf243c41537bd22c483ecca6781592d8cc366701c68c0421fd1dcfa2654201019d3bbc56f6adc3705195b5d5f65a9e5203f92b475dd68ecdb8583e8f2772c8dbb244157f9a38f68655d5ebcf7e4d2b432f1a94f6c1fc5276118339dd8b98b437184553fdfce0cd60e48896c2884dfe7e337fe08cb3e65d8676ca67cb4519da848d80299aa62b10f412cdab357fb4f7cc6faa078d9cb3ab7b909209c3647740060af4e04bfd887b70a290f57b4967941c4d94a174e293cbf46d32961dd6e9c43c4460d63404b2c9262f0d16e9374b9422688aef3328db44ce7dddcc1a122feedc62bebbdad44486d71026005f69346369dfec43aa874d99550ff8c65e6f49453cb383c11c1150eb838bfe7fd78656cec1b07e613ddf59a8532d88236755f6d248b731d429a9ed5e8214a28a2eda2e54ff13d4cea8392b25ba86dd0a390a8a14e134bd7e2c6197a98bff2e245d59dc16ed3e9953d5370671c08da238e1de7cccba506ca66b6dbe2d11cc33e72a3798ee2a5280f7c1c68ca1871b3c377567f3ac24ec969c184b221cc90a37457d784456f6fa925b1fa3f533123cf1e64e90fe8d79eb563dc9838218d993ebf549a13fd3136f7b4c163b9fa6c879e2dccb4165008
# -*- Fundamental -*-
#
# (C) 2005 Tenable Network Security
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/RegisteredFeed.pdf
#  http://www.nessus.org/plugins/TenableCommercial.pdf
#  http://www.nessus.org/plugins/DirectFeed.pdf
#  http://www.nessus.org/plugins/DirectFeedCommercial.pdf
#
#
#
# @NOGPL@
#
# crypto_func.inc 
#


#---------------------------------------------------------#
# DES encryption code                                     #
#---------------------------------------------------------#



perm1 = make_list (57, 49, 41, 33, 25, 17,  9,
                     1, 58, 50, 42, 34, 26, 18,
                    10,  2, 59, 51, 43, 35, 27,
                    19, 11,  3, 60, 52, 44, 36,
                    63, 55, 47, 39, 31, 23, 15,
                     7, 62, 54, 46, 38, 30, 22,
                    14,  6, 61, 53, 45, 37, 29,
                    21, 13,  5, 28, 20, 12,  4 );


perm2 = make_list (14, 17, 11, 24,  1,  5,
                     3, 28, 15,  6, 21, 10,
                    23, 19, 12,  4, 26,  8,
                    16,  7, 27, 20, 13,  2,
                    41, 52, 31, 37, 47, 55,
                    30, 40, 51, 45, 33, 48,
                    44, 49, 39, 56, 34, 53,
                    46, 42, 50, 36, 29, 32 );

perm3 = make_list (58, 50, 42, 34, 26, 18, 10,  2,
                    60, 52, 44, 36, 28, 20, 12,  4,
                    62, 54, 46, 38, 30, 22, 14,  6,
                    64, 56, 48, 40, 32, 24, 16,  8,
                    57, 49, 41, 33, 25, 17,  9,  1,
                    59, 51, 43, 35, 27, 19, 11,  3,
                    61, 53, 45, 37, 29, 21, 13,  5,
                    63, 55, 47, 39, 31, 23, 15,  7 );

perm4 = make_list (32,  1,  2,  3,  4,  5,
                     4,  5,  6,  7,  8,  9,
                     8,  9, 10, 11, 12, 13,
                    12, 13, 14, 15, 16, 17,
                    16, 17, 18, 19, 20, 21,
                    20, 21, 22, 23, 24, 25,
                    24, 25, 26, 27, 28, 29,
                    28, 29, 30, 31, 32,  1 );

perm5 = make_list (16,  7, 20, 21,
                    29, 12, 28, 17,
                     1, 15, 23, 26,
                     5, 18, 31, 10,
                     2,  8, 24, 14,
                    32, 27,  3,  9,
                    19, 13, 30,  6,
                    22, 11,  4, 25 );

perm6 = make_list (40,  8, 48, 16, 56, 24, 64, 32,
                    39,  7, 47, 15, 55, 23, 63, 31,
                    38,  6, 46, 14, 54, 22, 62, 30,
                    37,  5, 45, 13, 53, 21, 61, 29,
                    36,  4, 44, 12, 52, 20, 60, 28,
                    35,  3, 43, 11, 51, 19, 59, 27,
                    34,  2, 42, 10, 50, 18, 58, 26,
                    33,  1, 41,  9, 49, 17, 57, 25 );

sc = make_list (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1);

sbox =    make_list (        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
                              0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
                              4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
                             15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
	                  
                             15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
		              3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
			      0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
			     13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
	                  
                             10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
		             13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
			     13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
			      1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,

	                      7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
		             13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
			     10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
			      3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,

	                      2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
		             14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
			      4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
			     11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,

		             12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
		             10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
			      9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
			      4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,

		              4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
		             13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
			      1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
			      6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,

	                     13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
		              1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
			      7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
			      2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 );

function permute (in, p)
{
 local_var buf, i;

 buf = NULL;
 for (i = 0; i < strlen(p); i++)
    buf += in[ord(p[i]) - 1];
 
 return buf;
}

function lshift (d, count)
{
 local_var buf, i;

 buf = NULL;
 for (i = 0; i < strlen(d); i++)
   buf += d[(i+count)%strlen(d)];
  
 return buf;
} 

function xor (in1, in2)
{
 local_var buf, i;

 buf = NULL;
 for (i = 0; i < strlen(in2); i++)
   buf += raw_string (ord(in1[i]) ^ ord(in2[i]));
 
 return buf;
}


global_var _b, _er, _erk, _cb, _pcb, _l, _r, _r2, _buf;

_b = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

_er = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

_erk = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

_cb = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

_pcb = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

_l = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

_r = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

_r2 = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

__buf = make_list (
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

function des_encrypt (in, key, type)
{
 local_var i, j, k, c, d, cd, pd1, l, r, rl, pk1;
 local_var cb, pcb, r2, tmp, val, ki;
 local_var m, n;
 local_var cmpt, tmp1, tmp2, count;
 
 pk1 = c = d = cd = NULL;

 for (cmpt = 0; cmpt < 56; cmpt++)
   pk1 += key[perm1[cmpt] - 1];

 c = substr (pk1, 0, 27);
 d = substr (pk1, 28, 55);

 for (i = 0; i < 16; i++)
 {
  tmp1 = tmp2 = NULL;
  count = sc[i];
  for (cmpt = 0; cmpt < 28; cmpt++)
  {
    tmp1 += c[(cmpt+count)%28];
    tmp2 += d[(cmpt+count)%28];
  }

  c = tmp1;
  d = tmp2;

  cd = c + d;

  ki[i] = NULL;
  for (cmpt = 0; cmpt < 48; cmpt++)
    ki[i] += cd[perm2[cmpt] - 1];
 }

 for (cmpt = 0; cmpt < 64; cmpt++)
 {
  if (cmpt < 32)
    _l[cmpt] = in[perm3[cmpt] - 1];
  else
    _r[cmpt-32] = in[perm3[cmpt] - 1];
 }

 
 for (i = 0; i < 16; i++)
 {
  for (cmpt = 0; cmpt < 48; cmpt++)
     _er[cmpt] = _r[perm4[cmpt] - 1];

  if (type == 1)
  { 
    tmp2 = ki[i];
    for (cmpt = 0; cmpt < 48; cmpt++)
      _b[cmpt] = (_er[cmpt] ^ ord(tmp2[cmpt]));
  }
  else
  {
    tmp2 = ki[15-i];
    for (cmpt = 0; cmpt < 48; cmpt++)
      _b[cmpt] = (_er[cmpt] ^ ord(tmp2[cmpt]));
  }

  for (j = 0; j < 8; j++)
  {
   tmp2 = j*6;
   m = (_b[tmp2] << 1);
   m = m | (_b[tmp2 + 5]);

   n = (_b[tmp2 + 1] << 3);
   n = n | (_b[tmp2 + 2] << 2);
   n = n | (_b[tmp2 + 3] << 1);
   n = n | (_b[tmp2 + 4]);

   tmp1 = sbox [j*4*16 + m*16 + n];
   for (k = 0; k < 4; k++)
      if ((tmp1 & (1<<(3-k))) == 0)
        _b[tmp2 + k] = 0;
      else
        _b[tmp2 + k] = 1;
  }
 
  for (j=0; j<8; j++)
  {
   tmp2 = j*6;
   tmp1 = j*4;
   _cb[tmp1] = _b[tmp2];
   _cb[tmp1+1] = _b[tmp2+1];
   _cb[tmp1+2] = _b[tmp2+2];
   _cb[tmp1+3] = _b[tmp2+3];
  }

  for (cmpt = 0; cmpt < 32; cmpt++)
    _pcb[cmpt] = _cb[perm5[cmpt] - 1];
 
  for (cmpt = 0; cmpt < 32; cmpt++)
    _r2[cmpt] = (_l[cmpt] ^ _pcb[cmpt]);

  _l = _r;
  _r = _r2;
 }
 
 for (cmpt = 0; cmpt < 64; cmpt++)
 {
   tmp2 = perm6[cmpt]-1;
   if (tmp2 < 32)
     __buf[cmpt] = _r[tmp2];
   else
     __buf[cmpt] = _l[tmp2-32];
 }

 return __buf;
}


global_var _zero, _one, _inb;

_zero = raw_string(0);
_one = raw_string(1);

_inb = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

function set_des_key (key)
{
 local_var keyb, i;

 keyb = NULL;

 for (i=0;i<64;i++)
 {

  if ((ord(key[i/8]) & (1<<(7-(i%8)))) == 0)
    keyb += _zero;
  else
    keyb += _one;
 }

 return keyb;
}


function str_to_key (str)
{
 local_var key, i;

 key = raw_string ( ((ord(str[0])>>1) << 1) ,
                    ((((ord(str[0])&0x01)<<6) | (ord(str[1])>>2)) << 1) ,
                    ((((ord(str[1])&0x03)<<5) | (ord(str[2])>>3)) << 1) ,
                    ((((ord(str[2])&0x07)<<4) | (ord(str[3])>>4)) << 1) ,
                    ((((ord(str[3])&0x0F)<<3) | (ord(str[4])>>5)) << 1) ,
                    ((((ord(str[4])&0x1F)<<2) | (ord(str[5])>>6)) << 1) ,
                    ((((ord(str[5])&0x3F)<<1) | (ord(str[6])>>7)) << 1) ,
                    ((ord(str[6])&0x7F) << 1) );

 return set_des_key(key:key);
}


function DES (in, key, _string, type)
{
 local_var inb, keyb, key2, outb, out, buf, i;

 inb = keyb= outb = buf = NULL;;

 if (isnull(_string) || (_string == TRUE))
   key2 = str_to_key (str:key);
 else
   key2 = key;

 for (i=0;i<64;i++)
 {
  if ((ord(in[i/8]) & (1<<(7-(i%8)))) == 0)
    _inb[i] = 0;
  else
    _inb[i] = 1;    
 }

 outb = des_encrypt(in:_inb, key:key2, type:type);

 out = make_list (0,0,0,0,0,0,0,0);

 for (i=0;i<64;i++) 
 {
  if (outb[i] == 1)
    out[i/8] = out[i/8] | (1<<(7-(i%8)));
 }

 for (i=0;i<8;i++)
 {
  buf += raw_string (out[i]);
 }

 return buf;
}





#---------------------------------------------------------#
# RC4 HMAC encryption code                                #
#---------------------------------------------------------#

global_var arcS, arcS2;

function arcfour_setkey (key)
{
 local_var i,j,temp;

 arcS = NULL;
 for (i=0; i < 256; i++)
 {
  arcS[i] = i;
  arcS2[i] = ord(key[i % strlen(key)]);
 }

 j = 0;
 
 for (i=0; i < 256; i++)
 {
  j = (j + arcS[i] + arcS2[i]) % 256;
  temp = arcS[i];
  arcS[i] = arcS[j];
  arcS[j] = temp;
 }
}


function ARCFOUR (data)
{
 local_var i,j,temp,t,k,output,l;

 output = NULL;
 i = j = 0;
 
 for (l=0; l < strlen(data); l++)
 {
  i = (i+1) % 256;
  j = (j + arcS[i]) % 256;
  temp = arcS[i];
  arcS[i] = arcS[j];
  arcS[j] = temp;
  t = (arcS[i] + arcS[j]) % 256;
  k = arcS[t];

  output += raw_string (k ^ ord(data[l]));
 }

 return output;
}


function rc4_hmac_string_to_key (string)
{
 # Must be unicode !!!
 return MD4 (string);
}


function rc4_hmac_checksum (key,type,data,real_key)
{
 local_var hmac, tmp, key2;

 hmac = HMAC_MD5 (key:key, data:"signaturekey"+raw_byte(b:0));
 tmp = MD5 (type+data);
 
 return HMAC_MD5 (key:hmac, data:tmp);
}


function rc4_hmac_encrypt (key,data,type,real_key)
{
 local_var hmac, checksum, conf_data, K3, random, key2, val1, i;

 if (isnull(real_key) || (real_key == FALSE))
   key2 = rc4_hmac_string_to_key (string:key);
 else
   key2 = key;
 
 random = NULL;
 
 hmac = HMAC_MD5 (key:key2, data:type);

 for (i=0; i < 8; i++)
    random += raw_string (rand() % 256);
 conf_data = random + data;

 checksum = HMAC_MD5 (key:hmac, data:conf_data);
 K3 = HMAC_MD5 (key:hmac, data:checksum);

 arcfour_setkey (key:K3);
 val1 = ARCFOUR (data:conf_data);

 return checksum + val1;
}


function rc4_hmac_decrypt (key,data,type,real_key)
{
 local_var hmac, checksum, checksum2, conf_data, K3, key2, val1;

 if (isnull(real_key) || (real_key == FALSE))
   key2 = rc4_hmac_string_to_key (string:key);
 else
   key2 = key;
 
 hmac = HMAC_MD5 (key:key2, data:type);

 checksum = substr(data,0,15);
 K3 = HMAC_MD5 (key:hmac, data:checksum);


 conf_data = substr (data,16,strlen(data)-1);
 arcfour_setkey (key:K3);
 val1 = ARCFOUR (data:conf_data);

 checksum2 = HMAC_MD5 (key:hmac, data:val1);

 if (checksum == checksum2)
   return substr(val1,8,strlen(val1)-1);
 else
   return NULL;
}


#function rc4_hmac_checksum (key,data,type)
#{
# ksign = HMAC_MD5;
#}


#---------------------------------------------------------#
# DES-cbc  encryption code                                #
#---------------------------------------------------------#


function xor8 (a,b)
{
 local_var tmp, i;

 tmp = NULL;

 for (i=0; i<strlen(a); i++)
   tmp += raw_byte (b:ord(a[i]) ^ ord(b[i]));

 return tmp;
}


function reverse(i)
{
 local_var tmp, val, j;

 tmp = 0;
 val = 0x80;
 for (j=1; j<8; j++)
 {
  if (ord(i) & val)
    tmp += (1 << j);
  val = val >> 1;
 }

 return raw_byte(b:tmp);
}


function reverse8 (s)
{
 local_var tmp, i;

 tmp = NULL;

 for (i=0; i<strlen(s); i++)
   tmp += reverse(i:s[strlen(s)-1-i]);

 return tmp;
}


function get_parity (i)
{
 local_var tmp, val, j;

 tmp = 0;
 val = 2;
 for (j=0; j<7; j++)
 {
   if (i & val)
     tmp++;
   val = (val << 1) % 256;
 }

 return (tmp%2);
}


function fixparity(s)
{
 local_var tmp, val, i;

 tmp = NULL;
 for (i=0; i<strlen(s);i++)
 {
  val = ord(s[i]);
  if (get_parity(i:val) == 0)
   val = (val & 0xFE) + 1 ;
  else
   val = val & 0xFE;

  tmp += raw_byte(b:val);
 }

 return tmp;
}

function removeMSBits(s)
{
 local_var tmp, i;

 tmp = NULL;
 for (i=0; i<strlen(s); i++)
 {
  tmp += raw_byte(b:ord(s[i]) << 1);
 }

 return tmp;
}


# Need to be done
function is_weak_key (key)
{
 return 0;
}


function des_cbc_checksum (key, data, iv)
{
 local_var tout0, tout1, tin0, tin1, i, tin, keyb, tmp;

 tout0 = get_dword(blob:iv, pos:0);
 tout1 = get_dword(blob:iv, pos:4);

 keyb = set_des_key (key:key);

 for (i=0; i<strlen(data); i+=8)
 {
  if (i+8<=strlen(data))
  {
   tin0 = get_dword(blob:data, pos:i);
   tin1 = get_dword(blob:data, pos:i+4);
  }
  else
  {
   tmp = substr(data,i,strlen(data)-1);
   tmp += crap(data:raw_byte(b:0), length:8-(strlen(tmp)%8));
   tin0 = get_dword(blob:tmp, pos:i);
   tin1 = get_dword(blob:tmp, pos:i+4);   
  }

  tin0 = tin0 ^ tout0;
  tin1 = tin1 ^ tout1;
  
  tin = raw_dword (d:tin0) + raw_dword(d:tin1);
  tin = DES (in:tin, key:keyb, type:1, _string:FALSE);
  tout0 = get_dword(blob:tin, pos:0);
  tout1 = get_dword(blob:tin, pos:4);
 }

 return raw_dword(d:tout0) + raw_dword(d:tout1);
}


function des_cbc_encrypt (data, key, iv, encrypt)
{
 local_var tin, tin0, tin1, tout0, tout1, out, i, xor0, xor1, keyb;

 keyb = set_des_key (key:key);

 out = NULL;
 if (encrypt == 1)
 {
  tout0 = get_dword(blob:iv, pos:0);
  tout1 = get_dword(blob:iv, pos:4);
  for (i=0; i<strlen(data); i+=8)
  {
   tin0 = get_dword(blob:data, pos:i);
   tin1 = get_dword(blob:data, pos:i+4);

   tin0 = tin0 ^ tout0;
   tin1 = tin1 ^ tout1;
  
   tin = raw_dword (d:tin0) + raw_dword(d:tin1);
   tin = DES (in:tin, key:keyb, type:1, _string:FALSE);
   tout0 = get_dword(blob:tin, pos:0);
   tout1 = get_dword(blob:tin, pos:4);
   out += tin;
  }
 }
 else
 {
  xor0 = get_dword(blob:iv, pos:0);
  xor1 = get_dword(blob:iv, pos:4);
  for (i=0; i<strlen(data); i+=8)
  {
   tin0 = get_dword(blob:data, pos:i);
   tin1 = get_dword(blob:data, pos:i+4);
   tin = raw_dword(d:tin0) + raw_dword(d:tin1);
   tin = DES (in:tin, key:keyb, type:0, _string:FALSE);
   tout0 = get_dword(blob:tin, pos:0) ^ xor0;
   tout1 = get_dword(blob:tin, pos:4) ^ xor1;
   out += raw_dword(d:tout0) + raw_dword(d:tout1);
   xor0 = tin0;
   xor1 = tin1;
  }
 }

 return out;
}


function des_cbc_string_to_key (_string,salt)
{
 local_var odd, s, tempkey, byteblock, i, j, key, fix_weak;

 fix_weak = raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xF0);

 odd = 1;

 s = _string + salt;
 tempkey = raw_string (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
 
 # pad on 8 bytes
 if (strlen(s) % 8)
   s = s + crap (data:raw_byte(b:0x00), length:8-(strlen(s)%8));

 for (i=0; i< strlen(s); i+=8)
 {
  byteblock = removeMSBits(s:substr(s,i,i+7));
  if (odd == 0)
  {
   odd = 1;
   byteblock = reverse8(s:byteblock);
  }
  else
   odd = 0;

  tempkey = xor8 (a:tempkey, b:byteblock);
 }

 tempkey = fixparity(s:tempkey);
 if (is_weak_key(key:key))
   key = xor8 (a:key, b:fix_weak);
 key = des_cbc_checksum(key:tempkey,data:s, iv:tempkey);
 key = fixparity(s:key);

 return key;
}


function des_cbc_md5_encrypt (data, key)
{
 local_var iv, confounder, i, hash, cksum, tmp;

 cksum = raw_string (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);

 confounder = NULL;

 for (i=0; i<8; i++)
  confounder += raw_byte(b:rand()%256);

 tmp = data;
 if (strlen(data)%8)
   tmp += crap(data:raw_byte(b:0),length:8-(strlen(data)%8));

 hash = MD5 (confounder+cksum+tmp);

 iv = raw_string (0,0,0,0,0,0,0,0);

 return des_cbc_encrypt (data:confounder+hash+tmp, key:key, iv:iv, encrypt:1);
}



function des_cbc_md5_decrypt (data, key)
{
 local_var iv, confounder, cksum, decrypted, hash, msg, tohash;

 cksum = raw_string (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);

 iv = raw_string (0,0,0,0,0,0,0,0);

 decrypted = des_cbc_encrypt (data:data, key:key, iv:iv, encrypt:0);
 if (strlen(decrypted) < 24)
   return NULL;
 
 msg = substr(decrypted,24,strlen(decrypted)-1);
 confounder = substr(decrypted, 0, 7);
 tohash = confounder+cksum+msg;

 hash = MD5 (tohash);

 cksum = substr(decrypted, 8, 23);

 if (hexstr(cksum) >!< hexstr(hash))
   return NULL;

 return msg;
}


function des_cbc_md5_checksum (data, key)
{
 local_var confounder, iv, i, enckey, tmp;

 iv = raw_string (0,0,0,0,0,0,0,0);

 enckey = xor8(a:key,b:raw_string(0xF0,0xF0,0xF0,0xF0,0xF0,0xF0,0xF0,0xF0));
 confounder = NULL;

 for (i=0; i<8; i++)
  confounder += raw_byte(b:rand()%256);

 return des_cbc_encrypt (data:confounder+MD5(confounder+data), key:enckey, iv:iv, encrypt:1);
}




#---------------------------------------------------------#
# LANMAN2.1 Challenge/Response                            #
#---------------------------------------------------------#


function LM_Hash (password)
{
 local_var len, pass, K1, K2, hash;

 len = strlen (password) & 14;
 pass = substr (password, 0, len);

 while (strlen(pass) < 14)
   pass += raw_string (0);

 pass = toupper (pass);

 K1 = substr (pass, 0, 6);
 K2 = substr (pass, 7, 13);

 hash = DES (in:"KGS!@#$%", key:K1, type:1) + DES (in:"KGS!@#$%", key:K2, type:1);

 return hash;
}


function LM_Response (password, challenge)
{
 local_var hash, key1, key2, key3, response;

 response = NULL;

 hash = LM_Hash (password:password);
 response[1] = substr (hash, 0, 7) + raw_string (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);

 hash += raw_string (0x00,0x00,0x00,0x00,0x00);

 key1 = substr (hash, 0, 6);
 key2 = substr (hash, 7, 13);
 key3 = substr (hash, 14, 20);

 response[0] = DES (in:challenge, key:key1, type:1) + DES (in:challenge, key:key2, type:1) + DES (in:challenge, key:key3, type:1);

 return response;
}




#---------------------------------------------------------#
# NTLM 0.12 Challenge/Response                            #
#---------------------------------------------------------#


function NTLM_Hash (password)
{
 if (password)
   return MD4 (password);
 else
   return raw_string(0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0);
}

function NTLM_Response (password, challenge)
{
 local_var hash, key1, key2, key3, response;

 response = NULL;
 hash = NTLM_Hash (password:password);

 response[1] = MD4 (hash);

 hash += raw_string (0x00,0x00,0x00,0x00,0x00);

 key1 = substr (hash, 0, 6);
 key2 = substr (hash, 7, 13);
 key3 = substr (hash, 14, 20);

 response[0] = DES (in:challenge, key:key1, type:1) + DES (in:challenge, key:key2, type:1) + DES (in:challenge, key:key3, type:1);

 return response;
}


function NTLMv2_Hash (password, login, domain)
{
 local_var hash, user, dest, data;

 hash = NTLM_Hash (password:password);
 user = toupper (login);
 dest = domain;
 
 data = user + dest;
 hash = HMAC_MD5 (data:data, key:hash);

 return hash;
}


# Not used : Broken #
function NTLMv2_Response (password, login, domain, challenge)
{
 local_var hash, data, blob, hmac, resp, TimeStamp, blip, i;

 resp = NULL;
 hash = NTLMv2_Hash (password:password, login:login, domain:domain);

 blip = NULL;

 for (i = 0; i < 8; i++)
    blip += raw_string (rand() % 256);
 
 TimeStamp = raw_string (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00) ; # To change !!
 
 blob = raw_string ( 0x01,                    # Response Type Identification Number
                     0x01,                    # Maximum Response Type Identification Number
		     0x00, 0x00,              # Reserved
		     0X00, 0x00, 0x00, 0x00 ) # Reserved ?
	+
	TimeStamp
	+
	blip
	+
	raw_string (0x00,0x00,0x00,0x00)  # Unknown value
	+
	raw_string (0x00,0x00,0x00,0x00)  # List of Netbios Name. Emtpy for the moment.
	+
	raw_string (0x00,0x00,0x00,0x00); # Unknown value
	
 data = challenge + blob;
 hmac = HMAC_MD5 (data:data, key:hash);
 resp[0] = hmac + blob;
 resp[1] = HMAC_MD5 (data:hash, key:hmac);

 return resp;
}


function LMv2_Response (password, login, domain, challenge)
{
 local_var hash, data, blob, hmac, resp, TimeStamp, blip, i;
 
 resp = NULL;
 hash = NTLMv2_Hash (password:password, login:login, domain:domain);

 blip = NULL;

 for (i = 0; i < 8; i++)
    blip += raw_string (rand() % 256);
 
 data = challenge + blip;
 hmac = HMAC_MD5 (data:data, key:hash);
 resp[0] = hmac + blip;
 resp[1] = HMAC_MD5 (data:hmac, key:hash);

 return resp;
}
