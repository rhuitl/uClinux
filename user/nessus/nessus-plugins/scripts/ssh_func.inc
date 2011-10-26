#TRUSTED 5f15411781ba8038fda865265ba2da641dcc5193bc4fb9211d07c4b01efd174c365bdc2fe52aefe952d6e8d124128b97ea9fbe2e337e68b451a2a98f8b6672328bd132ce6c4c19ddb286bae38dd72c4d876446643756b340cc9161bda5eaa11945dcf43cd66b41d599e143a2f96b5c6d54bcc03a94ec507158baab1409a07106dc2a350caee6f65116d066f483b31c78201d61e5e5c804549910ee32876473b62cdbdbde6c7ccbf10d3f3d183dd841763e46ec36809fa702e1859838edddb040db94bad2865273d285e4ac1c10fab1c619fb81aeece1a1f5ea19e8eb16343ca127d01b59983dec04de8cfe4e631449e854191703ebe0861da48067918d9c369fa84fb2c6344a583f663fad0be452b6270fafa2dddfe318ff0a1cc4df243fbfba6d7f1d4f3536857db340730e3090924a42ca21b0d16316d58155e37eb71e875e4bcfab8a5c7896a7c7eb685cde4cb315d0aa1eda286409cc74b1846488c5821a061e90b96e4873d35c2348e1d8f3505ee84c6fef13167033de8971a1255ded1ac2224b54e93ff07cef90fa6f403d5cdc851dc5be6a39165238d9dfb59137830f1cf63e15b6a0317b6cd93c04a00541384cc2a41a0f8cc0814453f78c8788b6b604c3a9cf70fe8ded363e547900a17a65cee0460e916d61b088eb31b9368e9ca124f8a4f2d8819d4f9218b8e9751f36bd6c0a7bcef8c2d35e7b9706f3dc93c896
#------------------------------------------------------------------------------
#
# 
# (C) 2005 - 2006 Tenable Network Security
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
# @NOGPL@
#
#

include ("kerberos_func.inc");

global_var session_id, enc_keys, seqn_w, seqn_r;
global_var local_channel, remote_channel;
global_var l_window_size, received_size;
global_var r_window_size, r_packet_size;
global_var dh_pub, dh_priv;
global_var _ssh_banner;
global_var _ssh_server_version;
global_var _ssh_supported_authentication;
global_var _ssh_cmd_error;
global_var _ssh_error;
global_var _reuse_connection;
global_var bugged_sshd, bugged_first, bugged_channels, bugged_rws, bugged_rps;
global_var initial_window_size, max_packet_size;


# ssh_hex2raw() copied from misc_func.inc as we don't want to taint ssh_func.inc with
# a third-party include
function ssh_hex2raw(s)
{
 local_var i, j, ret, l;

 s = chomp(s);  # remove trailing blanks, CR, LF...
 l = strlen(s);
 if (l % 2) display("ssh_hex2raw: odd string: ", s, "\n");
 for(i=0;i<l;i+=2)
 {
  if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
        j = int(s[i]);
  else
        j = int((ord(s[i]) - ord("a")) + 10);

  j *= 16;
  if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
        j += int(s[i+1]);
  else
        j += int((ord(s[i+1]) - ord("a")) + 10);
  ret += raw_string(j);
 }
 return ret;
}


function register_int_in_kb(int, name)
{
 if ( ! defined_func("replace_kb_item") || !_reuse_connection ) return 0;
 replace_kb_item(name:name, value:int);
}

function load_int_from_kb(name)
{
 if ( ! defined_func("get_kb_fresh_item") || !_reuse_connection ) return NULL;
 return get_kb_fresh_item(name);
}

function register_data_in_kb(data, name)
{
 local_var n, item;
 n = 0;
 if ( ! defined_func("replace_kb_item") || !_reuse_connection ) return 0;
 replace_kb_item(name:name, value:hexstr(data));
}

function load_data_from_kb(name)
{
 local_var item;
 if ( ! defined_func("get_kb_fresh_item") || !_reuse_connection ) return NULL;
 item =  get_kb_fresh_item(name);
 if ( isnull(item) ) return NULL;
 return ssh_hex2raw(s:item);
}

function register_array_in_kb(array, name)
{
 local_var i, item;
 if ( ! defined_func("replace_kb_item") || !_reuse_connection ) return 0;
 for ( i = 0 ; i < max_index(array); i ++ )
 {
  replace_kb_item(name:name + "_" + i, value:hexstr(array[i]));
 }
}

function register_intarray_in_kb(array, name)
{
 local_var i, item;
 if ( ! defined_func("replace_kb_item") || !_reuse_connection ) return 0;
 for ( i = 0 ; i < max_index(array); i ++ )
 {
  replace_kb_item(name:name + "_" + i, value:string(array[i]));
 }
}

function load_array_from_kb(name)
{
 local_var array, n, item;

 if ( ! defined_func("get_kb_fresh_item") || !_reuse_connection ) return NULL;
 n = 0;
 array = make_list();
 while ( TRUE )
 {
  item = get_kb_fresh_item(name + "_" + n );
  if ( isnull(item) ) break;
  array[n] = ssh_hex2raw(s:item);
  n ++;
 }

 return array;
}

function load_intarray_from_kb(name)
{
 local_var array, n, item;

 if ( ! defined_func("get_kb_fresh_item") || !_reuse_connection ) return NULL;
 n = 0;
 array = make_list();
 while ( TRUE )
 {
  item = get_kb_fresh_item(name + "_" + n );
  if ( isnull(item) ) break;
  array[n] = int(item);
  n ++;
 }

 return array;
}

function kb_ssh_login()
{
 return string(get_kb_item("Secret/SSH/login"));
}

function kb_ssh_password()
{
 return string(get_kb_item("Secret/SSH/password"));
}

function kb_ssh_privatekey()
{
 return string(get_kb_item("Secret/SSH/privatekey"));
}

function kb_ssh_publickey()
{
 return string(get_kb_item("Secret/SSH/publickey"));
}

function kb_ssh_passphrase()
{
 return string(get_kb_item("Secret/SSH/passphrase"));
}

function kb_ssh_realm()
{
 return string(get_kb_item("Secret/SSH/realm"));
}

function kb_ssh_host()
{
 return get_host_name();
}

function kb_ssh_transport()
{
 local_var r;
 r = get_kb_item("Services/ssh");

 if ( r ) return int(r);
 else return 22;
}


#-----------------------------------------------------------------#
# Set SSH debugging error msg                                     #
#-----------------------------------------------------------------#
function set_ssh_error(msg)
{
 _ssh_error = msg;
}


#-----------------------------------------------------------------#
# Get SSH debugging error msg                                     #
#-----------------------------------------------------------------#
function get_ssh_error()
{
 return _ssh_error;
}


#-----------------------------------------------------------------#
# Get SSH server's version                                        #
#-----------------------------------------------------------------#
function get_ssh_supported_authentication()
{
 return _ssh_supported_authentication;
}


#-----------------------------------------------------------------#
# Get SSH server's version                                        #
#-----------------------------------------------------------------#
function get_ssh_server_version()
{
 return _ssh_server_version;
}


#-----------------------------------------------------------------#
# Get SSH banner                                                  #
#-----------------------------------------------------------------#
function get_ssh_banner()
{
 return _ssh_banner;
}


#-----------------------------------------------------------------#
# Convert network long (buffer) to long                           #
#-----------------------------------------------------------------#
function ntol(buffer,begin)
{
 local_var len;

 len = 16777216*ord(buffer[begin]) +
       ord(buffer[begin+1])*65536 +
       ord(buffer[begin+2])*256 +
       ord(buffer[begin+3]);

 return len;
}

#-----------------------------------------------------------------#
# Convert int to network long (raw_string)                        #
#-----------------------------------------------------------------#
function raw_int32(i)
{
 local_var buf;

 buf = raw_string (
		 (i>>24) & 255,
        (i>>16) & 255,
        (i>>8) & 255,
        (i) & 255
		 );
 return buf;
}

#-----------------------------------------------------------------#
# Convert char to network char (raw_string)                       #
#-----------------------------------------------------------------#
function raw_int8(i)
{
 local_var buf;

 buf = raw_string (
        (i) & 255
		 );
 return buf;
}


#-----------------------------------------------------------------#
# Init packet sequence number and channel number                  #
#-----------------------------------------------------------------#
function init()
{
 # sequence packet = 0
 seqn_w = seqn_r = 0;
 local_channel = 0;
 _ssh_banner = "";
 _ssh_server_version = "";
 _ssh_supported_authentication = "";
 _ssh_cmd_error = "";
 _ssh_error = "";
 initial_window_size = 32768*2;
 max_packet_size = initial_window_size/2;
 bugged_sshd = 0;
 bugged_first = 1;
 register_int_in_kb (int:bugged_sshd, name:"Secret/SSH/bugged_sshd");
 #register_int_in_kb (int:bugged_first, name:"Secret/SSH/bugged_first");

}


#-----------------------------------------------------------------#
# Decode base64 string - ported from public domain code           #
#-----------------------------------------------------------------#
function base64decode(str)
{
 local_var len, i, j, k, ret, base64, b64, a,b,c,o;
 len = strlen(str);
 ret = "";

 base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

 for (i = 0; i < 256; i++)
   b64[i] = 0;
 for (i = 0; i < strlen(base64); i++)
   b64[ord(base64[i])] = i;

 for(j=0;j<len;j+=4)
 {
   for (i = 0; i < 4; i++)
   {
    c = ord(str[j+i]);
    a[i] = c;
    b[i] = b64[c];
   }
 
   o[0] = (b[0] << 2) | (b[1] >> 4);
   o[1] = (b[1] << 4) | (b[2] >> 2);
   o[2] = (b[2] << 6) | b[3];
   if (a[2] == ord('='))
     i = 1;
   else if (a[3] == ord('='))
     i = 2;
   else
     i = 3;
   for(k=0;k<i;k++)
      ret += raw_int8(i:o[k]);
   
   if (i < 3) 
     break;
 }

 return ret;
}


#-----------------------------------------------------------------#
# Reads a SSH packet (comes from smb_nt.inc)                      #
#-----------------------------------------------------------------#
function ssh_recv(socket, length)
{
  local_var header, len, trailer, cmpt, payload, ret;

  header = recv(socket:socket, length:4, min:4);
  if (strlen(header) < 4)return(NULL);
  len = ntol (buffer:header, begin:0);
  if ((len == 0) || (len > max_packet_size)) return(header);
  trailer = recv(socket:socket, length:len, min:len);
  if(strlen(trailer) < len )return(NULL);
 
  seqn_r++;
  register_int_in_kb(name:"Secret/SSH/seqn_r", int:seqn_r);

  # SSH servers can send IGNORE (code 2) or BANNER (code 53) msg
  ret = ord(trailer[1]);
  if ((ret == 2) || (ret == 53))
  {
    if (ret == 53)
      _ssh_banner += getstring (buffer:trailer, pos:2);

    return ssh_recv(socket:socket, length:length);
  }

  return strcat(header, trailer);
}


#-----------------------------------------------------------------#
# Detect if remote ssh server is known to be bugged (SunSSH1.0)   #
#-----------------------------------------------------------------#
function is_sshd_bugged(banner)
{
 if (ereg(string:banner, pattern:"^SSH-2\.0-Sun_SSH_1\.0$"))
   return 1;

 return 0;
}


#-----------------------------------------------------------------#
# Waits for the server identification string, and sends our own   #
# identification string.                                          #
#-----------------------------------------------------------------#
function ssh_exchange_identification(socket)
{
 local_var buf, sshversion, num, prot;

 buf = recv_line(socket:socket, length:1024);

 if (!buf)
 {
   set_ssh_error(msg: "Nessus did not receive server's version");
   return 0;
 }

 # server ident : SSH-%d.%d-servername #
 if (!ereg(string:buf, pattern:"^SSH-*[0-9]\.*[0-9]-*[^\n]"))
 {
   set_ssh_error(msg: "Remote service is not a valid SSH service");
   return 0;
 }

 sshversion = split(buf, sep:"-", keep:0);
 num = split(sshversion[1], sep:".", keep:0);

 # version supported = 2 & 1.99
 if ((num[0] != 2) && !((num[0] == 1) && (num[1] == 99)))
 {
   set_ssh_error(msg: "Nessus only supports SSHv2");
   return 0;
 }

 # We use 2.0 protocol
 prot = "SSH-2.0-Nessus"+raw_string(0x0a);
 send(socket:socket, data:prot);

 if ( '\r\n' >< buf ) buf = buf - '\r\n';
   else buf = buf - '\n';

 if (is_sshd_bugged(banner:buf))
 {
   bugged_sshd = 1;
   register_int_in_kb (int:bugged_sshd, name:"Secret/SSH/bugged_sshd");
 }

 # all is correct
 return buf;
}


#-----------------------------------------------------------------#
# check pattern in buffer                                         #
# return next len in buffer or -1                                 #
#-----------------------------------------------------------------#
function check_pattern(buffer,pattern,length)
{
 local_var alglen, len, alg;

 alglen = ntol (buffer:buffer, begin:length);
 len = length+4+alglen;
 alg = substr(buffer,length+4,len-1);
 if (!ereg(string:alg, pattern:pattern))
  return -1;

 return len;
}

#-----------------------------------------------------------------#
# Create key exchange packet                                      #
#-----------------------------------------------------------------#
function kex_packet(payload,code)
{
 local_var len, padding_len, full_len, kex;

 len = 
   # padding length
     1 +
     # msg code
     1 +
     # payload length
     strlen(payload);
  
 #padding (mod 8) = 8 - ( (len+packet_len(4) ) % 8 ) 
 padding_len = 8 - ((len + 4) % 8);

 # if padding len is less than 4 add block size
 if (padding_len < 4)
   padding_len += 8;
 
 full_len = len + padding_len;

 kex =
    # packet length
    raw_int32 (i:full_len) +
    # padding length
    raw_int8 (i:padding_len) +
    #msg code (32 = Diffie-Hellman GEX Init)
    code +
    # Payload (Pub key)
    payload +
    # Padding
    crap(data:raw_string(0),length:padding_len);

 return kex;
}


#-----------------------------------------------------------------#
# mac compute                                                     #
#-----------------------------------------------------------------#
function mac_compute(data, type)
{
 local_var to_hash, hash;

 # we only support sha1! enc_keys[5] == mac_out key
 if (!type)
 {
  to_hash = raw_int32(i:seqn_w) + data;
  hash = HMAC_SHA1(data:to_hash, key:enc_keys[4]);
 }
 else
 {
  to_hash = raw_int32(i:seqn_r) + data;
  hash = HMAC_SHA1(data:to_hash, key:enc_keys[5]);
 }

 return hash;
}


#-----------------------------------------------------------------#
# crypt data                                                      #
#-----------------------------------------------------------------#
function crypt(data)
{
 local_var crypted;

 crypted = bf_cbc_encrypt(data:data, key:enc_keys[2], iv:enc_keys[0]);

 enc_keys[0] = crypted[1];

 register_array_in_kb(array:enc_keys, name:"Secret/SSH/enc_keys"); 
 return crypted[0];
}

#-----------------------------------------------------------------#
# decrypt data                                                    #
#-----------------------------------------------------------------#
function decrypt(data)
{
 local_var decrypted;

 decrypted = bf_cbc_decrypt(data:data, key:enc_keys[3], iv:enc_keys[1]);

 enc_keys[1] = decrypted[1];
 register_array_in_kb(array:enc_keys, name:"Secret/SSH/enc_keys"); 
 return decrypted[0];
}

#-----------------------------------------------------------------#
# Send ssh packet                                                 #
#-----------------------------------------------------------------#
function send_ssh_packet(socket,payload,code)
{
 local_var i, len, padding_len, full_len, buf, res, macbuf, crypted, padding;

 len = 
   # padding length
     1 +
     # msg code
     1 +
     # payload length
     strlen(payload);
  
 #padding (mod 8) = 8 - ( (len+packet_len(4) ) % 8 ) 
 padding_len = 8 - ((len + 4) % 8);

 # if padding len is less than 4 add block size
 if (padding_len < 4)
   padding_len += 8;
 
 full_len = len + padding_len;

 padding = "";
 for (i=0;i<padding_len;i++)
    padding = padding + raw_int8(i:(rand() % 256)); 


 buf =
    # packet length
    raw_int32 (i:full_len) +
    # padding length
    raw_int8 (i:padding_len) +
    #msg code (32 = Diffie-Hellman GEX Init)
    code +
    # Payload (Pub key)
    payload +
    # Padding
    padding;

 macbuf = mac_compute(data:buf, type:0);
 
 crypted = crypt(data:buf);

 buf = crypted + macbuf;

 send(socket:socket, data:buf);

 seqn_w++;
 register_int_in_kb(name:"Secret/SSH/seqn_w", int:seqn_w);
}


#-----------------------------------------------------------------#
# Receive ssh packet                                              #
#-----------------------------------------------------------------#
function recv_ssh_packet(socket, timeout)
{
 local_var len, need, padding_len, full_len, buf, res, macbuf, decrypted;
 local_var hmac, hmacbuf, mac, payload, ret;


 payload = raw_int8(i:0);

 # blockbytes = 8 for blowfish-cbc
 buf = recv(socket:socket, length:8, min:8, timeout:timeout);
 if (strlen(buf) != 8)
   return payload;
 
 decrypted = decrypt(data:buf);
 
 len = ntol(buffer:decrypted, begin:0);

 # Maximum packet size is 32768 bytes
 if (len > max_packet_size)
   return payload;
 # 8 = blocksize ... i know it is not generic and it will be hard to change all
 need = 4 + len - 8;
 buf = recv(socket:socket, length:need, min:need, timeout:timeout);
 if (strlen(buf) != need)
   return payload;
 
 decrypted = decrypted + decrypt(data:buf);

 # hmac-sha1 length = 20 ... same comment as before
 mac = recv(socket:socket, length:20, min:20, timeout:timeout);
 if (strlen(mac) != 20)
   return payload;

 macbuf = mac_compute(data:decrypted, type:1);

 hmac = hexstr(mac);
 hmacbuf = hexstr(macbuf);
 if (hmac >!< hmacbuf)
   return payload;

 payload = substr(decrypted, 5, strlen(decrypted)-ord(decrypted[4])-1);
 seqn_r++;
 register_int_in_kb(name:"Secret/SSH/seqn_r", int:seqn_r);

 # SSH servers can send IGNORE (code 2) or BANNER (code 53) msg
 ret = ord(payload[0]);
 if ((ret == 2) || (ret == 53) || ret == 4)
 {
   if (ret == 53)
     _ssh_banner += getstring (buffer:payload, pos:1);

   return recv_ssh_packet(socket:socket, timeout:timeout);
 }

 return payload;
}


#-----------------------------------------------------------------#
# Get payload from packet                                         #
#-----------------------------------------------------------------#
function packet_payload(packet,code)
{
 local_var packetlen, paddinglen, msgcode, payload;

 packetlen = ntol(buffer:packet, begin:0);
 paddinglen = ord(packet[4]);
 msgcode = ord(packet[5]);
 
 # Diffie-Hellman Key Exchange Reply
 if (msgcode != code)
  return 0;
 
 payload = substr(packet,6,packetlen-1);
 return payload;
}

#-----------------------------------------------------------------#
# Get string (lenght,string)                                      #
#-----------------------------------------------------------------#
function getstring(buffer,pos)
{
 local_var buf_len, buf;

 buf_len = ntol (buffer:buffer,begin:pos);
 buf = substr(buffer,pos+4,pos+4+buf_len-1);

 return buf;
}

#-----------------------------------------------------------------#
# Put string (string)                                             #
#-----------------------------------------------------------------#
function putstring(buffer)
{
 local_var buf;

 buf = raw_int32(i:strlen(buffer)) + buffer;
 
 return buf;
}

#-----------------------------------------------------------------#
# Put bignum (string)                                             #
#-----------------------------------------------------------------#
function putbignum(buffer)
{
 local_var len, buf;

 if (ord(buffer[0]) & 0x80)
 {
   len = strlen(buffer)+1;
   buf = raw_int32(i:len) + raw_string(0x00) + buffer;
 }
 else   
   buf = raw_int32(i:strlen(buffer)) + buffer;
 
 return buf;
}

#-----------------------------------------------------------------#
# RSA verify signature                                            #
#-----------------------------------------------------------------#
function ssh_rsa_verify(e, n, signature, data)
{
 local_var hash, id_sha1, sigtype, nlen,
	next, tmp_sig, siglen, len, sig,
	hdecoid, hshaoid, hhash, decrypted ;

#comes directly from OpenBSD
 id_sha1 = raw_string(
	0x30, 0x21, 
	0x30, 0x09,
	0x06, 0x05,
	0x2b, 0x0e, 0x03, 0x02, 0x1a, 
	0x05, 0x00,
	0x04, 0x14 
	);

 if (!n)
   return 0;

 sigtype = getstring(buffer:signature, pos:0);
 if (sigtype >!< "ssh-rsa")
   return 0;

 nlen = strlen(n);
 if (ord(n[0]) == 0)
   nlen--;
 
 # check minimum n size
 if ( (nlen*8) < 768 )
   return 0;

 next = 4 + strlen(sigtype);
 tmp_sig = getstring(buffer:signature,pos:next);
 siglen = strlen(tmp_sig);

 # bad signature (should be less than n)
 if (siglen > nlen)
   return 0;
 
 # Add padding if needed
 if (siglen < nlen)
 { 
   len = nlen - siglen;
   sig = crap(data:raw_string(0x00), length:len) + tmp_sig;
 }
 else
   sig = tmp_sig;

 hash = SHA1(data);

 if (strlen(hash) != 20)
   return 0;

 # must call RSA_public_decrypt from openssl, so convert arg - see ssh-rsa.c
 decrypted = rsa_public_decrypt(sig:sig,e:e,n:n);
 if (!decrypted)
   return 0;
 
 if (strlen(decrypted) != (strlen(id_sha1)+20))
   return 0;

 hdecoid = hexstr(substr(decrypted,0,strlen(id_sha1)-1));
 hshaoid = hexstr(id_sha1);

 if (hdecoid >!< hshaoid)
   return 0; 

 hdecoid = hexstr(substr(decrypted,strlen(id_sha1),strlen(decrypted)-1));
 hhash = hexstr(hash);

 if (hdecoid >!< hhash)
   return 0; 

 return 1;
}


#-----------------------------------------------------------------#
# DSA verify signature                                            #
#-----------------------------------------------------------------#
function ssh_dss_verify(p, q, g, pub, signature, data)
{
 local_var sigtype, next, tmp_sig, siglen, r, s, hash;

 sigtype = getstring(buffer:signature, pos:0);
 if (sigtype >!< "ssh-dss")
   return 0;

 next = 4 + strlen(sigtype);
 tmp_sig = getstring(buffer:signature,pos:next);
 siglen = strlen(tmp_sig);

 r = substr(tmp_sig,  0, 19);
 s = substr(tmp_sig, 20, 39);

 hash = SHA1(data);

 return dsa_do_verify(p:p,g:g,q:q,pub:pub,r:r,s:s,data:hash);
}


#-----------------------------------------------------------------#
# Derive keys  (this function works because we only use sha1 and  #
# blowfish so keylen is 20 due to sha1)                           #
#-----------------------------------------------------------------#
function derive_keys(hash,shared,session_id)
{
 local_var c, i, to_hash, keys;
 # c = 'A';
 c = 65;
 for (i = 0;i < 6; i++)
 {
   to_hash = putbignum(buffer:shared) + hash + raw_int8(i:c) + session_id;
   keys[i] = SHA1(to_hash);
   c++;
 }

 #         MODE OUT  MODE IN
 # enc.iv    0         1
 # enc.key   2         3
 # mac.key   4         5

 return keys;
}


#-----------------------------------------------------------------#
# Check is public key is correct                                  #
#-----------------------------------------------------------------#
function dh_valid_key(key, p)
{
 local_var val,i;

 if (ord(key[0]) > 0x80)
   return 0;

 val = 0;
 for(i=0;i<strlen(key);i++)
 {
  val = val + ord(key[i]);
  if (val > 1)
    break;
 }

 # ok if key < p
 if ((val>1) && (bn_cmp(key1:key,key2:p) == -1))
   return 1;

 return 0;
}


#-----------------------------------------------------------------#
# Genereate dh public & private keys                              #
#-----------------------------------------------------------------#
function dh_gen_key(p, g)
{
 local_var tries,keys,need;
 
 dh_pub = dh_priv = "";

 tries = 0;

 if (!p)
   return keys;

 # { "blowfish-cbc", 	SSH_CIPHER_SSH2, 8, 16, EVP_bf_cbc }
 # hash = sha1 = 20 (len) = 20 * 8 (bits)
 need = 20 * 8;

 # need won't be > than INT_MAX / 2
 # maybe we must test if 2*need >= numbits ...
 #if (need > INT_MAX / 2 || 2 * need >= BN_num_bits(dh->p))
 #  return keys;

 for (tries = 0; tries < 10; tries++)
 {
   dh_priv = bn_random(need:(need*2));
   if (!dh_priv)
     return -1;
   dh_pub = dh_generate_key(p:p, g:g, priv:dh_priv);
   if (!dh_pub)
     return -1;
   if (dh_valid_key(key:dh_pub, p:p))
     break;
 }

 if (tries++ >= 10)
   return -1;

 return 0;
}


#-----------------------------------------------------------------#
# Waits for the server identification string, and sends our own   #
# identification string.                                          #
#-----------------------------------------------------------------#
function ssh_kex2(socket,server_version)
{
 local_var packetlen, paddinglen, msgcode, len, len2;
 local_var a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p;
 local_var skexkex, kexr, skexr, gex, gexr, nk, nkey;
 local_var sinit, scookie, ccookie, cinit;
 local_var payload; 
 local_var keys, server_host_key_blob, shared; 
 local_var alg_type, type;
 local_var start, next, correct, groupex; 
 local_var rsa_e, rsa_n, dsa_p, dsa_q, dsa_g, dsa_pub_key; 
 local_var server_dh_public_key, signed_h, to_hash, hash;
 local_var key_exchange_algo, server_host_key_algo, enc_alg_client_to_server, enc_alg_server_to_client, mac_alg_client_to_server, mac_alg_server_to_client, cmp_alg_client_to_server, cmp_alg_server_to_client, client_version;
 local_var kex, skex, ret, codereq;
	

 # supported algorithms
 key_exchange_algo        = "diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1";
 server_host_key_algo     = "ssh-rsa,ssh-dss";
 enc_alg_client_to_server = "blowfish-cbc";
 enc_alg_server_to_client = "blowfish-cbc";
 mac_alg_client_to_server = "hmac-sha1";
 mac_alg_server_to_client = "hmac-sha1";
 cmp_alg_client_to_server = "none";
 cmp_alg_server_to_client = "none";

 # version
 client_version = "SSH-2.0-Nessus";


### Key exchange send client Init ###

 skex = ssh_recv(socket:socket, length:2000);
 if ( skex == NULL )
  {
   set_ssh_error(msg:"ssh_recv failed in ssh_kex2");
   return -1;
  }

 packetlen = ntol (buffer:skex, begin:0);
 paddinglen = ord(skex[4]);
 msgcode = ord(skex[5]);
 if (msgcode != 20)
 {
   set_ssh_error(msg:string("Received code was not SSH_MSG_KEXINIT (20). It was : ", msgcode));
   return -1;
 }

 sinit = substr(skex,6,packetlen+4-paddinglen-1);

 scookie = substr(skex,6,21);
 
 len = check_pattern(buffer:skex, pattern:"diffie-hellman-group-exchange-sha1", length:22);
 if (len == -1)
 {
   len = check_pattern(buffer:skex, pattern:"diffie-hellman-group1-sha1", length:22);
   if (len == -1)
   {
     set_ssh_error(msg:"Remote SSH server does not support DH exchanges (bugged ?)");
     return -1;
   }
   groupex = 0;
 }
 else
 {
  groupex = 1;
 }

 len2 = check_pattern(buffer:skex, pattern:"ssh-rsa", length:len);
 if (len2 == -1)
 {
   len2 = check_pattern(buffer:skex, pattern:"ssh-dss", length:len);
   if (len2 == -1)
   {
     set_ssh_error(msg:"Remote SSH server does not support DSA and RSA (bugged ?)");
     return -1;
   }
 }

 len = check_pattern(buffer:skex, pattern:enc_alg_client_to_server, length:len2);
 if (len == -1)
 {
  set_ssh_error(msg:"Remote SSH server does not support blowfish-cbc encryption");
  return -1;
 }

 len2 = check_pattern(buffer:skex, pattern:enc_alg_server_to_client, length:len);
 if (len2 == -1)
 {
  set_ssh_error(msg:"Remote SSH server does not support blowfish-cbc encryption");
  return -1;
 }

 len = check_pattern(buffer:skex, pattern:mac_alg_client_to_server, length:len2);
 if (len == -1)
 {
  set_ssh_error(msg:"Remote SSH server does not support hmac-sha1 encryption");
  return -1;
 }

 len2 = check_pattern(buffer:skex, pattern:mac_alg_server_to_client, length:len);
 if (len2 == -1)
 {
  set_ssh_error(msg:"Remote SSH server does not support hmac-sha1 encryption");
  return -1;
 }

 len = check_pattern(buffer:skex, pattern:cmp_alg_client_to_server, length:len2);
 if (len == -1)
 {
  set_ssh_error(msg:"Remote SSH server only supports compressed packets");
  return -1;
 }

 len2 = check_pattern(buffer:skex, pattern:cmp_alg_server_to_client, length:len);
 if (len2 == -1)
 {
  set_ssh_error(msg:"Remote SSH server only supports compressed packets");
  return -1;
 }


### Key exchange recv server Init ###

 ccookie = "";
 for (i=0;i<16;i++)
    ccookie = ccookie + raw_int8(i:(rand() % 256)); 

 cinit =
    # cookie (random)
    ccookie +
    # key algorithms (length + string)
    raw_int32(i:strlen(key_exchange_algo)) + key_exchange_algo +
    # server host key algorithms (length + string)
    raw_int32(i:strlen(server_host_key_algo)) + server_host_key_algo +
    # encryption algorithms client to server (length + string)
    raw_int32(i:strlen(enc_alg_client_to_server)) + enc_alg_client_to_server +
    # encryption algorithms server to client (length + string)
    raw_int32(i:strlen(enc_alg_server_to_client)) + enc_alg_server_to_client +
    # mac algorithms client to server (length + string)
    raw_int32(i:strlen(mac_alg_client_to_server)) + mac_alg_client_to_server +
    # mac algorithms server to client (length + string)
    raw_int32(i:strlen(mac_alg_server_to_client)) + mac_alg_server_to_client +
    # compression algorithms client to server (length + string)
    raw_int32(i:strlen(cmp_alg_client_to_server)) + cmp_alg_client_to_server +
    # compression algorithms server to client (length + string)
    raw_int32(i:strlen(cmp_alg_server_to_client)) + cmp_alg_server_to_client +
    # languages client to server (lenght)
    raw_int32(i:0) +
    # languages server to client (lenght)
    raw_int32(i:0) +
    # payload
    crap(data:raw_string(0x00), length:5);

 # msg code (20 = key exchange init)
 kex = kex_packet(payload:cinit,code:raw_string(0X14));

 send(socket:socket, data:kex);
 seqn_w++;
 register_int_in_kb(name:"Secret/SSH/seqn_w", int:seqn_w);


 if (groupex)
 {
  ### Key exchange Request : Diffie-Hellman GEX Request ###

  payload = raw_string(0x00,0x00,0x04,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x20,0x00);
  # msg code (34 = Diffie-Hellman GEX Request)
  kexr = kex_packet(payload:payload,code:raw_string(34));
 
  send(socket:socket, data:kexr);
  seqn_w++;
 register_int_in_kb(name:"Secret/SSH/seqn_w", int:seqn_w);


  ### Key exchange Reply : Diffie-Hellman Key Exchange Reply ###

  skexr = ssh_recv(socket:socket, length:1000);
  if ( skexr == NULL ) 
  {
   set_ssh_error(msg:"Connection timed out or was dropped during the key exchange");
   return -1;
  }

  # code = 31 (Diffie-Hellman Key Exchange Reply)
  payload = packet_payload(packet:skexr, code:31);
  if (!payload)
  {
   set_ssh_error(msg:"Received code was not SSH_MSG_KEXDH_REPLY (31)");
   return -1;
  }

  # get p bignum for dh group
  p = getstring (buffer:payload,pos:0);

  # get g bignum for dh group
  start = 4+strlen(p);
  g = getstring(buffer:payload,pos:start);
 }
 else
 {
  p = raw_string (0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                  0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
                  0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
                  0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
                  0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
                  0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
                  0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
                  0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
                  0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
                  0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
                  0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
                  0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
                  0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
                  0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
                  0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
                  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);

  g = raw_int8(i:2);
 }
 # generate public and private keys
 ret = dh_gen_key(p:p,g:g);
 if (ret != 0)
  {
   set_ssh_error(msg:"Error during DH keys generation");
   return -1;
  }

 register_data_in_kb(name:"Secret/SSH/dh_pub", data:dh_pub);
 register_data_in_kb(name:"Secret/SSH/dh_priv", data:dh_priv);

### Diffie Hellman GEX Init ###

 payload = raw_int32(i:strlen(dh_pub)) + dh_pub;

 if (groupex)
   codereq = raw_int8(i:32);
 else
   codereq = raw_int8(i:30);

 # msg code (32 = Diffie-Hellman GEX Init)
 gex = kex_packet(payload:payload,code:codereq);
 
 send(socket:socket, data:gex);
 seqn_w++;
 register_int_in_kb(name:"Secret/SSH/seqn_w", int:seqn_w);

### Diffie Hellman GEX Reply ###

 gexr = ssh_recv(socket:socket, length:2000);
 if ( gexr == NULL )
 {
  set_ssh_error(msg:"Connection timed out or was dropped during the key exchange");
  return -1;
 }

 if (groupex)
   codereq = 33;
 else
   codereq = 31;
 payload = packet_payload(packet:gexr, code:codereq);
 if (!payload)
 {
  set_ssh_error(msg:"Received code was not SSH_MSG_KEXDH_REPLY (31 or 33)");
  return -1;
 }
 
 # server host key blob
 server_host_key_blob = getstring (buffer:payload,pos:0);

 # extract server host key
 alg_type = getstring (buffer:server_host_key_blob, pos:0);
 next = 4 + strlen(alg_type);

 if (alg_type >< "ssh-rsa")
  {
   # rsa type == 0
   type = 0; 

   # e
   rsa_e = getstring (buffer:server_host_key_blob,pos:next);
   next = next + 4 + strlen(rsa_e);

   # n
   rsa_n = getstring (buffer:server_host_key_blob,pos:next);
   next = next + 4 + strlen(rsa_n);
  }
 else
  {
   if (alg_type >< "ssh-dss")
    {
     # dsa type == 1
     type = 1; 

     # p
     dsa_p = getstring (buffer:server_host_key_blob,pos:next);
     next = next + 4 + strlen(dsa_p);

     # q
     dsa_q = getstring (buffer:server_host_key_blob,pos:next);
     next = next + 4 + strlen(dsa_q);

     # g
     dsa_g = getstring (buffer:server_host_key_blob,pos:next);
     next = next + 4 + strlen(dsa_g);

     # pub key
     dsa_pub_key = getstring (buffer:server_host_key_blob,pos:next);
     next = next + 4 + strlen(dsa_pub_key);
    }
   else
    # bad key algo - should not occur
   {
     set_ssh_error(msg:"Server's host keys format is not supported");
     return -1;
   }
  }  


 # server dh public key
 start = 4 + strlen(server_host_key_blob);
 server_dh_public_key = getstring(buffer:payload,pos:start);

 # signed H
 start = start + 4 + strlen(server_dh_public_key);
 signed_h = getstring(buffer:payload,pos:start);
  
 if (!dh_valid_key(key:server_dh_public_key, p:p))
 {
   set_ssh_error(msg:"Server DH public key is not valid!");
   return -1;
 }

 # shared secret #
 shared = dh_compute_key(p:p,g:g,dh_server_pub:server_dh_public_key,
  pub_key:dh_pub,priv_key:dh_priv);
 if (!shared)
 {
   set_ssh_error(msg:"Error during shared secret computing");
   return -1;
 }

 # hash data
 to_hash = 
	# client version
	putstring(buffer:client_version) +
	# server version
	putstring(buffer:server_version) +
	# client cookie (cookielen,SSH_MSG_KEXINIT,cookie)
	raw_int32(i:(strlen(cinit)+1)) + raw_int8(i:20) + cinit +
	# server cookie (cookielen,SSH_MSG_KEXINIT,cookie)
	raw_int32(i:(strlen(sinit)+1)) + raw_int8(i:20) + sinit +
	# server host key blob
	putstring(buffer:server_host_key_blob);

 if (groupex)
 {
  to_hash += 
	# min,wantbits,max
	raw_string(0x00,0x00,0x04,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x20,0x00) +
	# p bignum
	putbignum(buffer:p) +
	# g bignum
	putbignum(buffer:g);
 }

 to_hash +=
	# public key bignum
	putbignum(buffer:dh_pub) +
	# server dh public key bignum
	putbignum(buffer:server_dh_public_key) +
	# shared bignum
	putbignum(buffer:shared);

 hash = SHA1(to_hash); 

 if (type == 0)
   correct = ssh_rsa_verify(e:rsa_e, n:rsa_n, signature:signed_h, data:hash);
 else
   # Not implemented
   correct = ssh_dss_verify(p:dsa_p, q:dsa_q, g:dsa_g, pub:dsa_pub_key, signature:signed_h, data:hash);

 if (!correct)
 {
   set_ssh_error(msg:"Server's signature is not valid!");
   return -1;
 }

 session_id = hash;
 register_data_in_kb(name:"Secret/SSH/session_id", data:session_id);
 enc_keys = derive_keys(hash:hash,shared:shared,session_id:session_id);
 register_array_in_kb(array:enc_keys, name:"Secret/SSH/enc_keys");

### New keys ###

 nkey = ssh_recv(socket:socket, length:1000);
 if ( nkey == NULL )
 {
  set_ssh_error(msg:"Connection was dropped or timed out during SSH_MSG_NEWKEYS");
  return -1;
 }
 # msg code (21 = New keys)
 payload = packet_payload(packet:nkey, code:21);
 if (!payload)
 {
  set_ssh_error(msg:"Received code was not SSH_MSG_NEWKEYS (21)");
  return -1;
 }

 payload = NULL;

 # msg code (21 = New keys)
 nk = kex_packet(payload:payload,code:raw_string(0x15));
 
 send(socket:socket, data:nk);
 seqn_w++;
 register_int_in_kb(name:"Secret/SSH/seqn_w", int:seqn_w);

 # all is correct
 return 0; 
}


#-----------------------------------------------------------------#
# Authenticate to SSH server                                      #
#-----------------------------------------------------------------#
function ssh_userauth2(socket, server_user, login, password, pub, priv, passphrase, kerberos, realm, host)
{
 local_var payload, buf, support, pass, pkey, kb, authenticated, blobpub, signature, blobpriv, privkey, typestr, next, e, n, hash2, hash, public, line, num, pubtab, i, crap, kb_ok, kerb, kerb_data, mic, message, sequence_number, to_hash, p, q, g, pub_key;

 pass = pkey = authenticated = kb = kerb = 0;

 payload = putstring(buffer:"ssh-userauth");

 # code 5 (SSH_MSG_SERVICE_REQUEST)
 send_ssh_packet(socket:socket, payload:payload, code:raw_string(0x05));

 # code 6 (SSH_MSG_SERVICE_ACCEPT)
 payload = recv_ssh_packet(socket:socket);
 if (ord(payload[0]) != 6)
 {
   set_ssh_error(msg:string("Server does not support ssh-userauth service. Received code was : " , ord(payload[0])));
   return -1;
 }

 # service accepted
 # code 50 (SSH_MSG_USERAUTH_REQUEST)
 # none request: we need to know what authentification server supports
 payload = putstring(buffer:server_user) + putstring(buffer:"ssh-connection") +
	putstring(buffer:"none");
 send_ssh_packet(socket:socket, payload:payload, code:raw_int8(i:50));

 # (51 == SSH_MSG_USERAUTH_FAILURE)
 payload = recv_ssh_packet(socket:socket);
 if (ord(payload[0]) != 51)
 {
   set_ssh_error(msg:string("Server did not reject none authentication method. Received code was : " , ord(payload[0])));
   return -1;
 }
 
 support = getstring(buffer:payload,pos:1);

 _ssh_supported_authentication = support;

 if (kerberos && realm && get_kb_item ("Secret/kdc_hostname"))
 {
   if (ereg(string:support, pattern:"gssapi-with-mic"))
     kerb = 1;
   else
   {
     set_ssh_error(msg:string("Error : Remote server does not support gssapi-with-mic authentication method! It supports : " , support));
     return -1;   
   }
 }
 else if (pub && priv)
 {
   if (ereg(string:support, pattern:"publickey"))
     pkey = 1;
   else
   {
     set_ssh_error(msg:string("Error : Remote server does not support publickey authentication method! It supports : " , support));
     return -1;   
   }
 }
 else if (password)
 {
   if (ereg(string:support, pattern:"password"))
     pass = 1;
   else if (ereg(string:support, pattern:"keyboard-interactive"))
     kb = 1;
   else
   {
     set_ssh_error(msg:string("Error : Remote server does not support one of the following password authentication methods : password, keyboard-interactive. It supports : " , support));
     return -1;   
   }
 }
 else
 {
   set_ssh_error(msg:"Nessus needs public and private keys or a password!");
   return -1;
 }
 

 if (kerb)
 {
  payload = putstring(buffer:server_user) + putstring(buffer:"ssh-connection") +
	putstring(buffer:"gssapi-with-mic") + raw_int32(i:1) + putstring(buffer:der_encode_oid(oid:"1.2.840.113554.1.2.2"))
	;
  send_ssh_packet(socket:socket, payload:payload, code:raw_int8(i:50));

  # code 60 (SSH_MSG_USERAUTH_GSSAPI_RESPONSE)
  payload = recv_ssh_packet(socket:socket);
  if (ord(payload[0]) == 60)
  {
   sequence_number = rand();

   # code 61 SSH_MSG_USERAUTH_GSSAPI_TOKEN
   kerb_data = kerberos_ssh (login:login, password:kerberos, realm:realm, host:host, seqnum:sequence_number);
   payload = putstring (buffer:kerb_data[1]);
   send_ssh_packet(socket:socket, payload:payload, code:raw_int8(i:61));

   payload = recv_ssh_packet(socket:socket);
   if (ord(payload[0]) == 61)
   {
    payload = check_gssapi_token (data:getstring(buffer:payload, pos:1), key:kerb_data[0], realm:realm, principal:login);
    if (!isnull(payload))
    {
     message = putstring(buffer:session_id) +
               raw_string (0x32) +
               putstring (buffer:server_user) +
               putstring (buffer:"ssh-connection") +
               putstring (buffer:"gssapi-with-mic");

     mic = gssapi_ssh_get_mic (data:message, key:kerb_data[0], seqnum:sequence_number);

     # code 66 SSH_MSG_USERAUTH_GSSAPI_MIC
     payload = putstring(buffer:mic);
     send_ssh_packet(socket:socket, payload:payload, code:raw_int8(i:66));

     # code 52 (SSH_MSG_USERAUTH_SUCCESS)
     payload = recv_ssh_packet(socket:socket);
     if (ord(payload[0]) == 52)
       authenticated = 1;  
    }
   }
  }

  if (!authenticated)
  {
    set_ssh_error(msg:"GSSAPI authentication failed");
    return -1;
  }
 }
 else if (pass)
 {
  # code 50 (SSH_MSG_USERAUTH_REQUEST)
  ###### need extra pad !!!! ######
  ###### Is it usefull ?? #####
  payload = putstring(buffer:server_user) + putstring(buffer:"ssh-connection") +
	putstring(buffer:"password") + raw_int8(i:0) + putstring(buffer:password)
	;

  send_ssh_packet(socket:socket, payload:payload, code:raw_int8(i:50));

  # code 52 (SSH_MSG_USERAUTH_SUCCESS)
  payload = recv_ssh_packet(socket:socket);
  if (ord(payload[0]) == 52)
     authenticated = 1;

  if (!authenticated)
  {
    set_ssh_error(msg:"Password authentication failed");
    return -1;
  }
 }
 else if (kb)
 {
  # code 50 (SSH_MSG_USERAUTH_REQUEST)
  payload = putstring(buffer:server_user) + putstring(buffer:"ssh-connection") +
	putstring(buffer:"keyboard-interactive") + putstring(buffer:"en-US") + putstring(buffer:"")
	;

  send_ssh_packet(socket:socket, payload:payload, code:raw_int8(i:50));

  # code 60 (SSH_MSG_USERAUTH_INFO_REQUEST)
  payload = recv_ssh_packet(socket:socket);
  if (ord(payload[0]) != 60)
  {
    set_ssh_error(msg:string("Server did not reply with SSH_MSG_USERAUTH_INFO_REQUEST during keyboard-interactive exchange. It replied with :", ord(payload[0])));
    return -1;
  }

  # Method name
  crap = getstring (buffer:payload,pos:1);
  next = 1 + 4 + strlen(crap);

  # Method name complement
  crap = getstring (buffer:payload,pos:next);
  next = next + 4 + strlen(crap);

  # Language
  crap = getstring (buffer:payload,pos:next);
  next = next + 4 + strlen(crap);
  
  # Number of request
  num = ntol(buffer:payload, begin:next);
  next += 4;

  kb_ok = 0;
  if (num > 0)
  {
    crap = getstring (buffer:payload,pos:next);
    if ("Password:" >< crap)
      kb_ok = 1;
  }

  if (!kb_ok)
  {
    set_ssh_error(msg:"Remote server keyboard-interactive method does not support Password.");
    return -1;   
  }

  # code 61 (SSH_MSG_USERAUTH_INFO_RESPONSE)
  payload = raw_int32(i:1) + putstring(buffer:password);

  send_ssh_packet(socket:socket, payload:payload, code:raw_int8(i:61));

  payload = recv_ssh_packet(socket:socket);
  
  # From draft-ietf-secsh-auth-kbdinteract-06.txt document :
  # Server should now send SSH_MSG_USERAUTH_INFO_REQUEST.
  # REQUEST can ask additionnal informations (like a new password).
  # But if all is correct num-prompts is set to 0 and client must
  # reply with an empty SSH_MSG_USERAUTH_INFO_RESPONSE.
  # So we just send an empty response and look if authentication
  # works. If remote server asked for additionnal informations,
  # authentication will just failed.
  if (ord(payload[0]) == 60)
  {
   # code 61 (SSH_MSG_USERAUTH_INFO_RESPONSE)
   payload = raw_int32(i:0);
   send_ssh_packet(socket:socket, payload:payload, code:raw_int8(i:61));
   payload = recv_ssh_packet(socket:socket);
  }
  if (ord(payload[0]) != 52)
  {
    set_ssh_error(msg:string("Server did not reply with SSH_MSG_USERAUTH_SUCCESS during keyboard-interactive exchange. It replied with :",ord(payload[0])));
    return -1;
  }
  
  authenticated = 1;
 }

 else if (!authenticated && pkey)
 {
  # SSH Public Key File Format (draft-ietf-secsh-publickeyfile-05.txt)
  # ---- BEGIN SSH2 PUBLIC KEY ----
  # Comment: "1024-bit RSA, converted from OpenSSH by galb@test1"
  # AAAAB3NzaC1yc2EAAAABIwAAAIEA1on8gxCGJJWSRT4uOrR13mUaUk0hRf4RzxSZ1zRbYY
  # Fw8pfGesIFoEuVth4HKyF8k1y4mRUnYHP1XNMNMJl1JcEArC2asV8sHf6zSPVffozZ5TT4
  # SfsUu/iKy9lUcCfXzwre4WWZSXXcPff+EHtWshahu3WzBdnGxm5Xoi89zcE=
  # ---- END SSH2 PUBLIC KEY ----
  if ("---" >< pub)
  {
    public = "";
    pubtab = split(pub, sep:'\n', keep:0);
    num = max_index(pubtab);
    for (i=0; i<num; i++)
    {
      line = pubtab[i];
      if (("---" >!< line) && (":" >!< line))
      {
        if ('\r' >< line)
          line -= '\r';
        public += line;
      }
    }      
  }
  else
  {
    # OpenSSH Public key file format
    public = ereg_replace(pattern:"[^ ]* ([^ ]*) [^ ]*$",
	                  string:pub,
		          replace:"\1");
  }

  blobpub = base64decode(str:public);

  # code 50 (SSH_MSG_USERAUTH_REQUEST)
  ###### need extra pad !!!! ######
  ###### Is it usefull ?? #####

  payload = putstring(buffer:server_user) + putstring(buffer:"ssh-connection") +
	putstring(buffer:"publickey") + raw_int8(i:1) ; 

  to_hash = putstring(buffer:session_id) + raw_int8(i:50);

  typestr = getstring(buffer:blobpub, pos:0);
  if ("ssh-rsa" >< typestr)
  {
    next = 4 + strlen(typestr);
    e = getstring(buffer:blobpub, pos:next);
    next = next + 4 + strlen(e);
    n = getstring(buffer:blobpub, pos:next);

    privkey = pem_to_rsa(priv:priv, passphrase:passphrase);
    if (!privkey)
     {
      set_ssh_error(msg:"Nessus failed to load SSH private key (RSA)");
      return -1;
     }

    payload += putstring(buffer:"ssh-rsa") + putstring(buffer:blobpub);

    to_hash += payload;

    hash = SHA1(to_hash);
    signature = rsa_sign(e:e, n:n, d:privkey, data:hash);
    if (!signature)
    {
      set_ssh_error(msg:"Error during client's RSA signature computing");
      return -1;
    }

    signature = putstring(buffer:"ssh-rsa") + putstring(buffer:signature);
  }
  else if ("ssh-dss" >< typestr)
  {
    # p
    next = 4 + strlen(typestr);
    p = getstring (buffer:blobpub,pos:next);
    next = next + 4 + strlen(p);

    # q
    q = getstring (buffer:blobpub,pos:next);
    next = next + 4 + strlen(q);

    # g
    g = getstring (buffer:blobpub,pos:next);
    next = next + 4 + strlen(g);

    # pub key
    pub_key = getstring (buffer:blobpub,pos:next);
 
    privkey = pem_to_dsa(priv:priv, passphrase:passphrase);
    if (!privkey)
    {
      set_ssh_error(msg:"Nessus failed to load SSH private key (DSA)");
      return -1;
    }

    payload += putstring(buffer:"ssh-dss") + putstring(buffer:blobpub);

    to_hash += payload;

    hash = SHA1(to_hash);
    signature = dsa_do_sign(p:p, q:q, g:g, pub:pub_key, priv:privkey, data:hash);
    if (!signature)
     {
      set_ssh_error(msg:"Error during client's DSA signature computing");
      return -1;
     }

    signature = putstring(buffer:"ssh-dss") + putstring(buffer:signature);

  }
  else
  {
    set_ssh_error(msg:"Client's private key type is not supported");
    return -1;
  }

  payload += putstring(buffer:signature);

  send_ssh_packet(socket:socket, payload:payload, code:raw_int8(i:50));

  # code 60 (SSH_MSG_USERAUTH_PK_OK)
  payload = recv_ssh_packet(socket:socket);
  if ((ord(payload[0]) == 52) || (ord(payload[0]) == 60))
     authenticated = 1;

  if (!authenticated)
  {
    payload = "Public key authentication failed.";
    if (password)
    {
      payload += '
It seems you provided both public/private keys and password.
In this case Nessus only use your public and private keys.
Nessus did not try both. As password authentication is
vulnerable to Man-In-The-Middle attack, that implies your keys
are useless (a "malicious server" will just reject your public
key authentication and accept any provided password).
';
    }
    set_ssh_error(msg:payload);

    return -1;
  }
 }

 # all is ok, user is authenticated
 return 0;
}


#-----------------------------------------------------------------#
# Open channel                                                    #
#-----------------------------------------------------------------#
function ssh_open_channel(socket)
{
 local_var payload, i, soc, ret;

 if (bugged_sshd && !bugged_first)
 {
   local_channel++;
   register_int_in_kb(name:"Secret/SSH/local_channel", int:local_channel);
   if (local_channel > 10)
     {
     soc = ssh_reuse_connection();
     if ( soc > 0 )
	shared_socket_destroy("Secret/SSH/socket");
     else 
	return -1;

     ret = ssh_login_or_reuse_connection();
     if ( ret == 0 )
	return -1;
     else 
       {  
        l_window_size = initial_window_size;
        received_size = 0;
        remote_channel = bugged_channels[local_channel];
        r_window_size  = bugged_rws[local_channel];
        r_packet_size  = bugged_rps[local_channel];
        register_int_in_kb(name:"Secret/SSH/remote_channel", int:remote_channel);
	return 0;
	}
   }

   l_window_size = initial_window_size;
   received_size = 0;
   remote_channel = bugged_channels[local_channel];
   r_window_size = bugged_rws[local_channel];
   r_packet_size = bugged_rps[local_channel];
   register_int_in_kb(name:"Secret/SSH/remote_channel", int:remote_channel);
   return 0;
 }

 local_channel++;
 register_int_in_kb(name:"Secret/SSH/local_channel", int:local_channel);

 # session = "session"
 # initial window size = 32768
 # maximum packet size = 32768
 l_window_size = initial_window_size;
 received_size = 0;
 payload = putstring(buffer:"session") + raw_int32(i:local_channel) +
	raw_int32(i:initial_window_size) + raw_int32(i:max_packet_size);

 # SSH_MSG_CHANNEL_OPEN == 90
 send_ssh_packet(socket:socket, payload:payload, code:raw_int8(i:90));

 # SSH_MSG_CHANNEL_OPEN_CONFIRMATION == 91 (92 == failure)
 payload = recv_ssh_packet(socket:socket);
 if (ord(payload[0]) != 91)
 {
   set_ssh_error(msg:string("Received code was not  SSH_MSG_CHANNEL_OPEN_CONFIRMATION (91). It was : " , ord(payload[0])));
   return -1;
 }

 remote_channel = ntol(buffer:payload, begin:5);
 register_int_in_kb(name:"Secret/SSH/remote_channel", int:remote_channel);
 r_window_size = ntol(buffer:payload, begin:9);
 r_packet_size = ntol(buffer:payload, begin:13);

 # For bugged channel like Sun_SSH_1.0 we create 10 channels at startup 
 # Sun_SSH supports only 10 channels at the same time.
 if (bugged_sshd)
 {
   bugged_first = 0;
   register_int_in_kb(int:bugged_first, name:"Secret/SSH/bugged_first");
   bugged_channels = bugged_rws = bugged_rps = NULL;
   bugged_channels[0] = 0;
   bugged_rws[0] = 0;
   bugged_rps[0] = 0;
   bugged_channels[local_channel] = remote_channel;
   for (i=local_channel+1; i < 11; i++)
   {
      payload = putstring(buffer:"session") + raw_int32(i:i) +
	  raw_int32(i:initial_window_size) + raw_int32(i:max_packet_size);

      send_ssh_packet(socket:socket, payload:payload, code:raw_int8(i:90));

      payload = recv_ssh_packet(socket:socket);
      if (ord(payload[0]) != 91)
      {
        set_ssh_error(msg:string("Received code was not  SSH_MSG_CHANNEL_OPEN_CONFIRMATION (91). It was : " , ord(payload[0])));
        return -1;
      }

      bugged_channels[i] = ntol(buffer:payload, begin:5);
      bugged_rws[i] = ntol(buffer:payload, begin:9);
      bugged_rps[i] = ntol(buffer:payload, begin:13);
   }

   register_intarray_in_kb(array:bugged_channels, name:"Secret/SSH/bugged_channels");
   register_intarray_in_kb(array:bugged_rws, name:"Secret/SSH/bugged_rws");
   register_intarray_in_kb(array:bugged_rps, name:"Secret/SSH/bugged_rps");
 }

 # all is ok, user is authenticated
 return 0;

}

#-----------------------------------------------------------------#
# Close channel                                                   #
#-----------------------------------------------------------------#
function ssh_close_channel(socket,end)
{
 local_var payload;

 # session = "session"
 # sender channel = 4444  / should we try different number on failure ?
 # initial window size = 32768
 # maximum packet size = 32768
 payload = raw_int32(i:remote_channel);

 # SSH_MSG_CHANNEL_CLOSE == 97
 send_ssh_packet(socket:socket, payload:payload, code:raw_int8(i:97));

 if (!end)
 {
   # SSH_MSG_CHANNEL_CLOSE == 97
   payload = recv_ssh_packet(socket:socket);

   while((ord(payload[0]) != 97) && (ord(payload[0]) != 0))
     payload = recv_ssh_packet(socket:socket);

   if (ord(payload[0]) != 97)
   {
     set_ssh_error(msg:string( "Received code was not  SSH_MSG_CHANNEL_CLOSE (97). It was : " , ord(payload[0])));
     return -1;
   }
 }

 # all is ok, user is authenticated
 return 0;

}


#-----------------------------------------------------------------#
# Login to SSH server                                             #
#-----------------------------------------------------------------#
function ssh_login(socket, login, password, pub, priv, passphrase, kerberos, realm, host)
{
 local_var server_user, ret, server_version;

 server_user = login;

 init();

 # Exchange protocol version identification strings with the server.
 server_version = ssh_exchange_identification(socket:socket);
 if (!server_version)
  return -1;

 _ssh_server_version = server_version;

 # key exchange
 # authenticate user
 ret = ssh_kex2(socket:socket, server_version:server_version);
 if (ret != 0)
   return -1;

 ret = ssh_userauth2(socket:socket, server_user:server_user, login:login, password:password, pub:pub, priv:priv, passphrase:passphrase, kerberos:kerberos, realm:realm, host:host);  
 if (ret != 0)
   return -1;

 # all is ok
 return 0;
}

 
#-----------------------------------------------------------------#
# Return size we can send on the channel and in the packet        #
#-----------------------------------------------------------------#
function get_data_size()
{
 local_var len;
 
 if (r_window_size <= r_packet_size)
    len = r_window_size;
 else
    len = r_packet_size;

 # packet option ~= 50 bytes
 len -= 50;

 # Remote server has not reajusted his window 
 if (len <= 0)
    return -1;

 return len;
}

 
#-----------------------------------------------------------------#
# Update Window channel size on SSH server                        #
#-----------------------------------------------------------------#
function update_window_size(socket,size)
{
 local_var len, payload;

 l_window_size -= size;
 received_size += size;

 # Maximum allocated memory is 20 MB
 # A correct server will send 32768 bytes packet. So we stop before
 # to get data.
 # A non standard server will just be stopped by nessusd.
 if (received_size > 19000000)
   return -1;

 if (l_window_size < max_packet_size)
 {
   len = initial_window_size - l_window_size;
   payload = raw_int32(i:remote_channel) + raw_int32(i:len);

   # SSH_MSG_CHANNEL_WINDOW_ADJUST == 93
   send_ssh_packet(socket:socket, payload:payload, code:raw_int8(i:93));

   l_window_size += len;   
 }

 return 0;
}



#-----------------------------------------------------------------#
# Execute command on SSH server                                   #
#-----------------------------------------------------------------#
function ssh_cmd(socket,cmd,timeout)
{
 local_var payload, ret, tempbuf, end, cret, val;

 # Flash error buffer
 _ssh_cmd_error = "";

 # Open channel
 ret = ssh_open_channel(socket:socket);
 if (ret != 0)
 {
   _ssh_cmd_error = "Nessus failed to open a new SSH channel. " + get_ssh_error();
   return NULL;
 }

 payload = raw_int32(i:remote_channel) + putstring(buffer:"exec") + raw_int8(i:0) +
	 putstring(buffer:cmd);

 # SSH_MSG_CHANNEL_REQUEST == 98
 send_ssh_packet(socket:socket, payload:payload, code:raw_int8(i:98));

 ret = NULL;

 # SSH_MSG_CHANNEL_SUCCESS == 99
 # while for previous useless messages (SSH_MSG_CHANNEL_WINDOW_ADJUST, ...)
 payload = recv_ssh_packet(socket:socket, timeout:timeout);

 while((ord(payload[0]) == 93) || (ord(payload[0]) == 95) || (ord(payload[0])  == 98))
 {
  if (ord(payload[0]) == 95)
  {
    payload = getstring(buffer:payload, pos:9);
    _ssh_cmd_error += payload;
    val = update_window_size(socket:socket,size:strlen(payload));
    if (val != 0)
      break;
  }
  payload = recv_ssh_packet(socket:socket, timeout:timeout);
 }

 while ((ord(payload[0]) != 97) && (ord(payload[0]) != 0))
 {
  if (ord(payload[0]) == 98)
  {
    payload = getstring(buffer:payload, pos:5);
    if ("exit-status" >!< payload)
      break;
  }
  else if ((ord(payload[0]) == 94) || (ord(payload[0]) == 95))
  {
    tempbuf = getstring(buffer:payload, pos:5);
    if (ord(payload[0]) == 94)
    {
      ret += tempbuf;
    }
    val = update_window_size(socket:socket,size:strlen(tempbuf));
    if (val != 0)
    {
      break;
    }
  }
  payload = recv_ssh_packet(socket:socket, timeout:timeout);
 }

 end = 0;
 if (ord(payload[0]) == 97)
   end = 1;

 # Close channel
 cret = ssh_close_channel(socket:socket, end:end);
 if (cret != 0)
 {
   _ssh_cmd_error = "Nessus failed to close SSH channel. " + get_ssh_error();
   return NULL;
 }

 return ret;
}


#-----------------------------------------------------------------#
# Return errors happended during ssh_cmd()                        #
#-----------------------------------------------------------------#
function ssh_cmd_error()
{
 return _ssh_cmd_error;
}



#------------------------------------------------------------------#
# Connection re-use                                                #
#------------------------------------------------------------------#

# Internal
function reuse_connection_init()
{
 _reuse_connection = 1;
 seqn_w = load_int_from_kb(name:"Secret/SSH/seqn_w");
 seqn_r = load_int_from_kb(name:"Secret/SSH/seqn_r");
 local_channel = load_int_from_kb(name:"Secret/SSH/local_channel");
 session_id = load_data_from_kb(name:"Secret/SSH/session_id");
 remote_channel = load_int_from_kb(name:"Secret/SSH/remote_channel");
 enc_keys = load_array_from_kb(name:"Secret/SSH/enc_keys"); 
 dh_pub = load_data_from_kb(name:"Secret/SSH/dh_pub"); 
 dh_priv = load_data_from_kb(name:"Secret/SSH/dh_priv");
 bugged_sshd = load_int_from_kb(name:"Secret/SSH/bugged_sshd");
 if (bugged_sshd)
 {
   bugged_channels = load_intarray_from_kb(name:"Secret/SSH/bugged_channels"); 
   bugged_rws = load_intarray_from_kb(name:"Secret/SSH/bugged_rws"); 
   bugged_rps = load_intarray_from_kb(name:"Secret/SSH/bugged_rps"); 
   bugged_first = load_int_from_kb(name:"Secret/SSH/bugged_first"); 
 }

 initial_window_size = 32768*2;
 max_packet_size = initial_window_size/2;

 if ( isnull(enc_keys) || isnull(dh_pub) || isnull(dh_priv) || isnull(session_id) ) return -1;
 return 0;
}


# Returns a socket to an already established connection 
function ssh_reuse_connection()
{
 local_var soc;

 if ( ! defined_func("shared_socket_acquire") ) 
	return 0;

 if ( reuse_connection_init() < 0 )
	{
	_reuse_connection = 0;
	return 0;
	}

 soc = shared_socket_acquire("Secret/SSH/socket");
 if ( soc == NULL ) 
  {
  _reuse_connection = 0;
  return 0;
  }
 else 
  return soc;
}


#
# Release the shared SSH connection so that another script can write to
# it
#
function ssh_close_connection()
{
 if ( _reuse_connection ) shared_socket_release("Secret/SSH/socket");
}



function ssh_login_or_reuse_connection()
{
 local_var soc;
 local_var login, password, pub, priv, passphrase, realm, host, kerberos;


 soc = ssh_reuse_connection();
 if ( soc > 0 ) return soc;

 login = kb_ssh_login();
 password = kb_ssh_password();
 pub = kb_ssh_publickey();
 priv = kb_ssh_privatekey();
 passphrase = kb_ssh_passphrase();
 realm = kb_ssh_realm();
 host = kb_ssh_host();
 kerberos = kb_ssh_password();

 if ( ! login || (! password &&  (! pub || ! priv))) return 0;


 soc = open_sock_tcp(kb_ssh_transport());
 if ( ! soc ) return 0;
 _reuse_connection = 1;
 if ( ssh_login(socket:soc, login:login, password:password, pub:pub, priv:priv, passphrase:passphrase, kerberos:kerberos, realm:realm, host:host) != 0 )
 {
  close(soc);
  return 0;
 }

 if ( shared_socket_register(name:"Secret/SSH/socket", socket:soc) < 0 )
	_reuse_connection = 0;

 return soc;
}
