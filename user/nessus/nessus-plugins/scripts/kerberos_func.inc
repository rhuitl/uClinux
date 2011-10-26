#TRUSTED 8c67d770a219840d35ab5cff57b45561866374e3d7bdbff431f745c89f5928376fcc8a39a2ff01f070d71bcfc3e1c899b80023483d14590b986f98e211e9418861b3dc659ede81bd5dc9e7e80aed4c65fc5ed3ead2a87317a8bf2a2584b7cd82920b8ad7337a128d5dc1f7994d382f00c54530475acc798e0884bbc4e7a14af8f92d7bf19c916f83684c029d66df8c8f5055e0200aa9f1094f160d383cf2e3e749e021f407ba33095b09eb94e1a905dbdcdc920e4a8e4dfee86310ad918221022796efbe57dafd2bba4b0fd7c1c0bbd1cd0a5415b3fe326591d5f05fa91fc70fadac553972846e89a9ad11577f5ef075158bcdcdf3e075bce8e841c4637ad70f37a3914e09e926026bcc9ab0ffb132892541f005ff097e823ce941525f4c4a1c07c18986aa0b354e384e55bd7ed554fee3957373a0bfc8f4e9dae23bfaff616f4e5022c948fff74a4232d1832f68b55300bbaf5b44db54bed79e1e6759902da13ad1f27b7f56dc7c06e601581f42bd6f88039608ac282c73f763344e66fcc351e22ec1f27578d72bfb9f7caf08f084098e2ef7069d5bb25c00d365bfcaa8acff100a290fe4311a51888605f06af387e6ddec5469f575e5bc1f2c313647fff26b23de36a354b29a6b80a89109873652ee2437487e40316361c8483cf4f9761f51805270f2e11d13245382f1d7d35ebfe6486981dbfaa37b392141dfd0c2c49720
# -*- Fundamental -*-
#
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
# @NOGPL@
#
# kerberos_func.inc 
#

include ('crypto_func.inc');


#---------------------------------------------------------#
# Function    : raw_byte                                  #
# Description : Convert a byte to raw data                #
#---------------------------------------------------------#

function raw_byte (b)
{
 return raw_string (b);
}


#---------------------------------------------------------#
# Function    : raw_word                                  #
# Description : Convert a word to raw data                #
#---------------------------------------------------------#

function raw_word (w)
{
 return raw_string ( (w)     & 255,
                     (w>>8)  & 255 );
}


#---------------------------------------------------------#
# Function    : raw_dword                                 #
# Description : Convert a dword to raw data               #
#---------------------------------------------------------#

function raw_dword (d)
{
 return raw_string ( (d)     & 255,
                     (d>>8)  & 255,
                     (d>>16) & 255,
                     (d>>24) & 255 );
}


#---------------------------------------------------------#
# Function    : get_byte                                  #
# Description : Extract a byte from a blob                #
#---------------------------------------------------------#

function get_byte (blob,pos)
{
 if (pos > (strlen (blob) - 1))
   return NULL;

 return ( ord(blob[pos]) );
}


#---------------------------------------------------------#
# Function    : get_word                                  #
# Description : Extract a word from a blob                #
#---------------------------------------------------------#

function get_word (blob,pos)
{
 if (pos > (strlen (blob) - 2))
   return NULL;

 return ( ord(blob[pos]) + (ord(blob[pos+1]) << 8) );
}


#---------------------------------------------------------#
# Function    : get_dword                                 #
# Description : Extract a dword from a blob               #
#---------------------------------------------------------#

function get_dword (blob, pos)
{
 if (pos > (strlen (blob) - 4))
   return NULL;

 return ( ord(blob[pos]) + 
          (ord(blob[pos+1]) << 8) +
          (ord(blob[pos+2]) << 16) +
          (ord(blob[pos+3]) << 24) );
}


#---------------------------------------------------------#
# Function    : get_checksum_type                         #
# Description : return checksum type                      #
#---------------------------------------------------------#

function get_checksum_type (enc_type)
{
 if (enc_type == 23)
   return -138;
 if (enc_type == 3)
   return 8;

 return 0;
}


#---------------------------------------------------------#
# Function    : supported_encryption_type                 #
# Description : check if encryption type is supported     #
#---------------------------------------------------------#

function supported_encryption_type (type)
{
 if ((type != 23) && # arcfour
     (type != 3)) # des-cbc-md5
   return FALSE;
 
 return TRUE;
}


#---------------------------------------------------------#
# Function    : kerberos_checksum                         #
# Description : checksum data                             #
#---------------------------------------------------------#

function kerberos_checksum (key, type, data, real_key, enc_type, realm, principal)
{
 local_var enckey;

 if (enc_type == 23)
   return rc4_hmac_checksum (key:key, type:type, data:data, real_key:real_key);
 if (enc_type == 3)
 {
  if (real_key == FALSE)
  {
    enckey = des_cbc_string_to_key (_string:key, salt:realm+principal);
  }
  else
    enckey = key;

  return des_cbc_md5_checksum (data:data, key:enckey);
 }

 return NULL;
}


#---------------------------------------------------------#
# Function    : kerberos_decrypt                          #
# Description : decrypt data                              #
#---------------------------------------------------------#

function kerberos_decrypt (key, type, data, real_key, enc_type, realm, principal)
{
 local_var enckey;

 if (enc_type == 23)
   return rc4_hmac_decrypt (key:key, type:type, data:data, real_key:real_key);
 if (enc_type == 3)
 {
  if (real_key == FALSE)
  {
    enckey = des_cbc_string_to_key (_string:key, salt:realm+principal);
  }
  else
    enckey = key;

  return des_cbc_md5_decrypt (data:data, key:enckey);
 }

 return NULL;
}


#---------------------------------------------------------#
# Function    : kerberos_encrypt                          #
# Description : encrypt data                              #
#---------------------------------------------------------#

function kerberos_encrypt (key, type, data, real_key, enc_type, realm, principal)
{
 local_var enckey;

 if (enc_type == 23)
   return rc4_hmac_encrypt (key:key, type:type, data:data, real_key:real_key);
 if (enc_type == 3)
 {
  if (real_key == FALSE)
    enckey = des_cbc_string_to_key (_string:key, salt:realm+principal);
  else
    enckey = key;

  return des_cbc_md5_encrypt (data:data, key:enckey);
 }

 return NULL;
}


#---------------------------------------------------------#
# Function    : der_length                                #
# Description : return raw der length of data             #
#---------------------------------------------------------#

function der_length (data)
{
 local_var tmp, length, len;

 length = NULL;
 len = strlen (data);

 while (len != 0)
 {
  length = raw_string (len % 256) + length;
  len = len / 256;
 }
 
 if ((strlen (length) > 1) || ((strlen(length) == 1) && (ord(length[0]) > 127)))
   length = raw_string (128 + strlen (length)) + length;

 return length;
}


#---------------------------------------------------------#
# Function    : der_encode                                #
# Description : Return der encoded data                   #
#---------------------------------------------------------#

function der_encode (tag,data)
{
 if (isnull (data))
   return NULL;

 return raw_string (tag) + der_length(data:data) + data;
}


function integer (i)
{
 local_var j,k;

 j = 0;

 for (k=0; k < strlen(i); k++)
 {
  j = j * 256 + ord(i[k]);
 }
 
 return j;
}


#---------------------------------------------------------#
# Function    : der_decode                                #
# Description : Return der decoded data                   #
#               [0] = code                                #
#               [1] = data                                #
#               [2] = next pos in buffer                  #
#---------------------------------------------------------#

function der_decode (data, pos)
{
 local_var tmp, i, j, len, len2;

 if (isnull (data))
   return NULL;
 
 if (isnull (pos))
   j = 0;
 else
   j = pos;

 if (strlen(data) - j  < 2)
   return NULL;

 tmp[0] = ord(data[j]);
 j++;
 
 len = ord(data[j]);
 j++;
 
 if (len > 127)
 {
  len -= 128;
  if (strlen(data) - j < len)
    return NULL;

  len2 = integer (i:substr (data, j, j + len - 1));
  j += len;
  len = len2;
 }
 
 if (strlen(data) - j < len)
   return NULL;

 tmp[1] = substr(data,j,j+len-1);
 tmp[2] = j + len;

 return tmp;
}


#---------------------------------------------------------#
# Function    : der_encode_oid                            #
# Description : Return der encoded OID (string)           #
#               ex: "1.2.840.113554.1.2.2"                #
#---------------------------------------------------------#

function der_encode_oid (oid)
{
 local_var nums, num, enum, i, max, encoded;

 if (isnull (oid))
   return NULL;

 nums = split (oid, sep:".", keep:0);
 
 max = max_index (nums);
 if (max < 2)
   return NULL;

 # value1 x 40 + value2
 encoded = raw_string (40*int(nums[0]) + int(nums[1]));
 
 for (i=2; i < max; i++)
 {
  num = int(nums[i]);
  enum = raw_string (num % 128);
  num = num / 128;
  while (num != 0)
  {
   enum = raw_string (128 + (num%128)) + enum;
   num = num / 128;
  }
  encoded += enum;
 }
 
 # OID Tag = 0x06
 return der_encode (tag:0x06, data:encoded);
}


#---------------------------------------------------------#
# Function    : der_decode_oid                            #
# Description : Return OID (string)                       #
#               ex: "1.2.840.113554.1.2.2"                #
#---------------------------------------------------------#

function der_decode_oid (oid)
{
 local_var soid, i, val;

 if (strlen (oid) < 1)
   return NULL;

 soid = string (ord (oid[0]) / 40, ".", ord (oid[0]) % 40);

 for (i = 1; i < strlen(oid); i++)
 {
  val = 0;
  while (ord(oid[i]) >= 128)
  {
   val = ((ord(oid[i]) - 128) + val) * 128;
   i++;
  }
  val += ord (oid[i]);
  soid += string (".",val);
 }
 
 return soid;
}


#---------------------------------------------------------#
# Function    : der_encode_int                            #
# Description : Return der encoded INTEGER                #
#---------------------------------------------------------#

function der_encode_int (i)
{
 local_var val,j,tmp;

 if (isnull (i))
   return NULL;

 val[0] = i & 255;
 val[1] = (i>>8)  & 255;
# val[2] = (i>>16) & 255;
# val[3] = (i>>24) & 255;

 j = 3;
 while ((val[j] == 0) && (j != 0))
   j--;

 tmp = NULL;
 while (j != 0)
 {
  tmp += raw_string (val[j]);
  j--;
 }

 tmp += raw_string (val[j]);
 
 return der_encode (tag:0x02, data:tmp);
}


#---------------------------------------------------------#
# Function    : der_encode_int32                          #
# Description : Return der encoded INTEGER                #
#---------------------------------------------------------#

function der_encode_int32 (i)
{
 local_var tmp;

 if (isnull (i))
   return NULL;

 tmp = raw_string ((i>>24) & 255,
                   (i>>16) & 255,
                   (i>>8)  & 255,
                   i & 255);

 return der_encode (tag:0x02, data:tmp);
}


#---------------------------------------------------------#
# Function    : der_encode_string                         #
# Description : Return der encoded STRING                 #
#---------------------------------------------------------#

function der_encode_string (string)
{
 if (isnull (string))
   return NULL;
   
 return der_encode (tag:0x1B, data:string);
}


#---------------------------------------------------------#
# Function    : der_encode_sequence                       #
# Description : Return der encoded SEQUENCE               #
#---------------------------------------------------------#


function der_encode_sequence (seq)
{
 local_var encoded, max, i, j, val;

 if (isnull (seq))
   return NULL;
   
 max = max_index (seq);
 if (max == 0)
   return NULL;

 i = 0xA0;
 
 encoded = NULL;
 
 for (j=0; j < max; j++)
 {
  val = seq[j];
  if (!isnull(val))
  {
    encoded += der_encode (tag:i, data:val);
  }
  i++;
 }

 # SEQUENCE Tag = 0x30
 return der_encode (tag:0x30, data:encoded); 
}


#---------------------------------------------------------#
# Function    : der_encode_name                           #
# Description : Return type/name                          #
#---------------------------------------------------------#
#                                                         #
# PrincipalName ::= SEQUENCE {                            #
#   name-type[0]     INTEGER,                             #
#   name-string[1]   SEQUENCE OF GeneralString            #
# }                                                       #
#                                                         #
#---------------------------------------------------------#

function der_encode_name (type, name1, name2)
{
 local_var list, names;

 if (isnull (name1) && isnull (name2))
   return NULL;
   
 list = NULL;
 
 names = der_encode_string (string:name1);
 names += der_encode_string (string:name2);
 
 list[0] = der_encode_int (i:type);
 list[1] = der_encode_list (list:names);

 return der_encode_sequence (seq:list); 
}


#---------------------------------------------------------#
# Function    : der_encode_time                           #
# Description : Return der encoded KerberosTime           #
#---------------------------------------------------------#

function der_encode_time (time)
{
 if (isnull (time))
   return NULL;
   
 return der_encode (tag:0x18, data:time);
}


#---------------------------------------------------------#
# Function    : der_parse_data                            #
# Description : Return der decoded data                   #
#---------------------------------------------------------#

function der_parse_data (tag,data)
{
 local_var tmp;

 tmp = der_decode (data:data);
 if (isnull (tmp) || (tmp[0] != tag))
   return NULL;

 return tmp[1];
}


#---------------------------------------------------------#
# Function    : der_parse_list                            #
# Description : Return der decoded list                   #
#---------------------------------------------------------#

function der_parse_list (list)
{
 local_var tmp,pos,i,ret;

 if (!list)
   return NULL;
 
 tmp = NULL;
 tmp[0] = 0;
 
 pos = 0;
 i = 1;
 while (pos < strlen(list))
 {
  ret = der_decode (data:list,pos:pos);
  if (isnull(ret))
    return NULL;
  
  tmp[i] = substr (list, pos, ret[2]);
  tmp[0] = tmp[0] + 1;
  pos = ret[2];
  i++;
 }

 return tmp;
}


#---------------------------------------------------------#
# Function    : der_parse_sequence                        #
# Description : Return der decoded sequence               #
#---------------------------------------------------------#

function der_parse_sequence (seq,num,list)
{
 local_var tmp, dseq, val, i, pos, ret;
 
 dseq = der_decode (data:seq);
 if (isnull(dseq) || (dseq[0] != 0x30))
   return NULL;

 if (!isnull(list) && (list == TRUE))
   return der_parse_list (list:dseq[1]);
 
 tmp = NULL;
 for (i=0; i < num; i++)
   tmp[i] = NULL;
 
 pos = i = 0;
 while (pos < strlen(dseq[1]))
 {
  ret = der_decode (data:dseq[1],pos:pos);
  if (isnull(ret))
    return NULL;
  
  val = ret[0] - 0xA0;
  if (val < 0)
    return NULL;
  
  tmp[val] = ret [1];
  pos = ret[2];
 }
 
 return tmp;
}


#---------------------------------------------------------#
# Function    : der_parse_int                             #
# Description : Return der decoded integer                #
#---------------------------------------------------------#

function der_parse_int (i)
{
 local_var tmp;

 tmp = der_parse_data (tag:0x02, data:i);
 if (!tmp)
   return NULL;

 tmp = integer (i:tmp);
 if (isnull(tmp))
   return NULL;

 return tmp;
}


#---------------------------------------------------------#
# Function    : der_parse_octet_string                    #
# Description : Return der decoded octet string           #
#---------------------------------------------------------#

function der_parse_octet_string (string)
{
 return der_parse_data (tag:0x04, data:string);
}


#---------------------------------------------------------#
# Function    : der_parse_oid                             #
# Description : Return der decoded oid                    #
#---------------------------------------------------------#

function der_parse_oid (oid)
{
 local_var tmp;

 tmp = der_parse_data (tag:0x06, data:oid);
 if (!tmp)
   return NULL;

 tmp = der_decode_oid (oid:tmp);
 if (!tmp)
   return NULL;

 return tmp;
}


#---------------------------------------------------------#
# Function    : der_parse_list_oid                        #
# Description : Return der decoded oid list               #
#               "oid1 oid2 ..."                           #
#---------------------------------------------------------#

function der_parse_list_oid (list)
{
 local_var tmp, seq, i;

 tmp = NULL;

 seq = der_parse_sequence (seq:list,list:TRUE);
 if (isnull(seq))
   return NULL;
 
 for (i=0;i < seq[0];i++)
 {
  tmp += der_parse_oid (oid:seq[i+1]) + " ";
 }

 return tmp;
}


#---------------------------------------------------------#
# Function    : der_encode_paenc                          #
# Description : Return der encoded PA-ENC                 #
#---------------------------------------------------------#
#                                                         #
# PA-ENC-TS-ENC ::= SEQUENCE {                            #
#   patimestamp [0] KerberosTime, -- client's time        #
#   pausec      [1] INTEGER OPTIONAL                      #
# }                                                       #
#                                                         #
#---------------------------------------------------------#

function der_encode_paenc(time)
{
 local_var paenc;

 paenc = NULL;
 paenc[0] = der_encode_time (time:time);
 paenc[1] = NULL;

 return der_encode_sequence (seq:paenc);
}


#---------------------------------------------------------#
# Function    : der_encode_octet_string                   #
# Description : Return der encoded OCTET STRING           #
#---------------------------------------------------------#

function der_encode_octet_string (string)
{
 return der_encode (tag:0x04, data:string);
}


#---------------------------------------------------------#
# Function    : der_encode_padata                         #
# Description : Return der encoded PA-DATA                #
#---------------------------------------------------------#
#                                                         #
# PA-DATA ::= SEQUENCE {                                  #
#   padata-type  [1] INTEGER,                             #
#   padata-value [2] OCTET STRING,                        #
# }                                                       #
#                                                         #
#---------------------------------------------------------#

function der_encode_padata (type,value)
{
 local_var pa_data;

 pa_data = NULL;

 pa_data[0] = NULL;
 pa_data[1] = der_encode_int (i:type);
 pa_data[2] = der_encode_octet_string (string:value);

 return der_encode_sequence (seq:pa_data);
}


#---------------------------------------------------------#
# Function    : der_encode_crypt                          #
# Description : Return der encoded/crypted structure      #
#---------------------------------------------------------#

function der_encode_crypt (data, key, type, enc_type, real_key, realm, principal)
{
 local_var crypted, encrypted_data;

 encrypted_data = kerberos_encrypt (key:key, type:raw_dword (d:type), data:data, real_key:real_key, enc_type:enc_type, realm:realm, principal:principal);

 crypted = NULL;
 crypted[0] = der_encode_int (i:enc_type);
 crypted[1] = NULL;
 crypted[2] = der_encode_octet_string (string:encrypted_data);

 return der_encode_sequence (seq:crypted);
}


#---------------------------------------------------------#
# Function    : der_encode_list                           #
# Description : Return der encoded list                   #
#---------------------------------------------------------#

function der_encode_list (list)
{
 return der_encode (tag:0x30, data:list);
}


#---------------------------------------------------------#
# Function    : der_encode_kdcreq                         #
# Description : Return der encoded KDC-REQ                #
#---------------------------------------------------------#
#                                                         #
# KDC-REQ ::= SEQUENCE {                                  #
#   pvno     [1] INTEGER,                                 #
#   msg-type [2] INTEGER,                                 #
#   padata   [3] SEQUENCE OF PA-DATA OPTIONAL,            #
#   req-body [4] KDC-REQ-BODY                             #
# }                                                       #
#                                                         #
#---------------------------------------------------------#

function der_encode_kdcreq (pvno, msg_type, list, req_body)
{
 local_var l;

 l = NULL;

 l[0] = NULL;
 l[1] = der_encode_int (i:pvno);
 l[2] = der_encode_int (i:msg_type);
 l[3] = der_encode_list (list:list);
 l[4] = req_body;

 return der_encode_sequence (seq:l);
}


function der_encode_request (req)
{
 local_var request;
 
 request = NULL;
 request[0] = der_encode (tag:0x01, data:req); 
 
 return der_encode_sequence(seq:request);
}



#---------------------------------------------------------#
# Function    : der_encode_kdc_req_body                   #
# Description : Return der encoded KDC-REQ-BODY           #
#---------------------------------------------------------#
#                                                         #
# KDC-REQ-BODY ::= SEQUENCE {                             #
#   kdc-options [0] KDCOptions,                           #
#   cname       [1] PrincipalName OPTIONAL,               #
#   realm       [2] Realm, -- Server's realm              #
#   sname       [3] PrincipalName OPTIONAL,               #
#   from        [4] KerberosTime OPTIONAL,                #
#   till        [5] KerberosTime,                         #
#   rtime       [6] KerberosTime OPTIONAL,                #
#   nonce       [7] INTEGER,                              #
#   etype       [8] SEQUENCE OF INTEGER, -- EncType       #
#   addresses   [9] HostAddresses OPTIONAL,               #
#   enc-authorization-data [10]  EncryptedData OPTIONAL,  #
#   additional-tickets     [11]  SEQUENCE OF Ticket OPT   #
# }                                                       #
#                                                         #
#---------------------------------------------------------#

function der_encode_kdc_req_body (principal,realm,service,hosts)
{
 local_var list, options;

 list = options = NULL;

 options = der_encode (tag:0x03, data:raw_string (0x00,0x00,0x00,0x00,0x00));
 
 list[0] = options;
 if (!isnull(principal))
   list[1] = der_encode_name (type:1, name1:principal, name2:NULL);
 else
   list[1] = NULL;
 list[2] = der_encode_string (string:realm);
 list[3] = service;
 list[4] = NULL;
 list[5] = der_encode_time (time:"20370913024805Z");
 list[6] = der_encode_time (time:"20370913024805Z");
 list[7] = der_encode_int (i:rand());
 # rc4-hmac-md5 , des-cbc-md5
 list[8] = der_encode_list (list:der_encode_int (i:23)+der_encode_int(i:3));
 if (!isnull(hosts))
   list[9] = der_encode_list (list:hosts);
 else
   list[9] = NULL;

 return der_encode_sequence (seq:list);
}


#---------------------------------------------------------#
# Function    : kerberostime                              #
# Description : Return KerberosTime Format                #
#               YYYYMMDDHHMMSSZ (Z = UTC time)            #
#---------------------------------------------------------#

function kerberostime()
{
 local_var tmp,time,conv,field;

 time = localtime(unixtime(),utc:TRUE);
 tmp = string (time["year"]);
 foreach field (make_list("mon", "mday", "hour", "min", "sec"))
 {
  conv = string (time[field]);
  if (strlen (conv) == 1)
    conv = "0" + conv;
  tmp += conv;
 }
 tmp += "Z";
 
 return tmp;
}

#---------------------------------------------------------#
# Function    : der_encode_asreq                          #
# Description : Return der encoded AS-REQ                 #
#---------------------------------------------------------#
#                                                         #
# AS-REQ ::= [APPLICATION 10] KDC-REQ                     #
#                                                         #
# KDC-REQ ::= SEQUENCE {                                  #
#   pvno     [1] INTEGER,                                 #
#   msg-type [2] INTEGER,                                 #
#   padata   [3] SEQUENCE OF PA-DATA OPTIONAL,            #
#   req-body [4] KDC-REQ-BODY                             #
# }                                                       #
#                                                         #
# PA-DATA ::= SEQUENCE {                                  #
#   padata-type  [1] INTEGER,                             #
#   padata-value [2] OCTET STRING,                        #
# }                                                       #
#                                                         #
# padata-type     ::= PA-ENC-TIMESTAMP                    #
# padata-value    ::= EncryptedData -- PA-ENC-TS-ENC      #
#                                                         #
# PA-ENC-TS-ENC ::= SEQUENCE {                            #
#   patimestamp [0] KerberosTime, -- client's time        #
#   pausec      [1] INTEGER OPTIONAL                      #
# }                                                       #
#                                                         #	    
#---------------------------------------------------------#

function der_encode_asreq (principal,realm,enc_type,password)
{
 local_var req_body, encoded, host, pa_enc, padata_enc, padata, pa_pac, request, service;
 
 pa_pac = request = service = NULL;

 pa_enc = der_encode_paenc (time:kerberostime());
 padata_enc = der_encode_crypt (data:pa_enc, key:password, type:1, enc_type:enc_type, real_key:FALSE, realm:realm, principal:principal);
 padata = der_encode_padata (type:2, value:padata_enc);

 request = der_encode_request (req:raw_string (0xFF));
 pa_pac = der_encode_padata (type:128, value:request);
 
 service = der_encode_name (type:2, name1:"krbtgt", name2:realm);
 req_body = der_encode_kdc_req_body (principal:principal, realm:realm, service:service);
 
 encoded = der_encode_kdcreq (pvno:5, msg_type:0x0A, list:padata+pa_pac, req_body:req_body);

 return der_encode (tag:0x6A, data:encoded);
}



#---------------------------------------------------------#
# Function    : der_decode_kdcrep                         #
# Description : Return der session key and Ticket         #
#---------------------------------------------------------#
#                                                         #
# AS-REP ::=    [APPLICATION 11] KDC-REP                  #
# KDC-REP ::=   SEQUENCE {                                #
#   pvno            [0]   INTEGER,                        #
#   msg-type        [1]   INTEGER,                        #
#   padata          [2]   SEQUENCE OF PA-DATA OPTIONAL,   #
#   crealm          [3]   Realm,                          #
#   cname           [4]   PrincipalName,                  #
#   ticket          [5]   Ticket,                         #
#   enc-part        [6]   EncryptedData                   #
# }                                                       #
#                                                         #
# EncryptedData ::=   SEQUENCE {                          #
#   etype           [0]   INTEGER, -- EncryptionType      #
#   kvno            [1]   INTEGER OPTIONAL,               #
#   cipher          [2]   OCTET STRING -- ciphertext      #
# }                                                       #
#                                                         #
# EncASRepPart ::=    [APPLICATION 25] EncKDCRepPart      #
# EncKDCRepPart ::=   SEQUENCE {                          #
#   key             [0]   EncryptionKey,                  #
#   last-req        [1]   LastReq,                        #
#   nonce           [2]   INTEGER,                        #
#   key-expiration  [3]   KerberosTime OPTIONAL,          #
#   flags           [4]   TicketFlags,                    #
#   authtime        [5]   KerberosTime,                   #
#   starttime       [6]   KerberosTime OPTIONAL,          #
#   endtime         [7]   KerberosTime,                   #
#   renew-till      [8]   KerberosTime OPTIONAL,          #
#   srealm          [9]   Realm,                          #
#   sname           [10]  PrincipalName,                  #
#   caddr           [11]  HostAddresses OPTIONAL          #
# }                                                       #
#                                                         #
#---------------------------------------------------------#

function der_decode_kdcrep (type,password, data, real_key)
{
 local_var buf,pvno,msg_type,pa_data,crealm,cname,ticket,enc_part,kvno,seq,enc_type,encrypted;
 local_var decrypted, enc_key;
 local_var resp, realm, principal;
 
 resp = NULL;

 buf = der_decode (data:data);
 if (isnull(buf) || ((buf[0] != 0x6B) && (buf[0] != 0x6D)))
   return NULL;
 
 # Data are in SEQUENCE
 seq = der_parse_sequence (seq:buf[1], num:7, list:FALSE);
 if (isnull(seq))
   return NULL;

 # PVNO == 5
 pvno = der_parse_int (i:seq[0]);
 if (isnull(pvno) || (pvno != 5))
   return NULL;

 # MSG-Type == AS-REP
 msg_type = der_parse_int (i:seq[1]);
 if (isnull(msg_type) || (msg_type != type))
   return NULL;

 # crealm
 crealm = seq[3];
 if (!crealm) return NULL;
 resp[2] = crealm;

 # cname 
 cname = seq[4];
 if (!cname) return NULL;
 resp[3] = cname;

 # TGT 
 ticket = seq[5];
 if (!ticket) return NULL;
 resp[0] = ticket;

 # enc-part 
 enc_part = seq[6];
 if (!enc_part) return NULL;
   
 # ENC-Part is a SEQUENCE
 seq = der_parse_sequence (seq:enc_part, num:3, list:FALSE);
 if (isnull(seq)) 
   return NULL;

 # Encryption type
 enc_type = der_parse_int (i:seq[0]);
 if (isnull(enc_type) || (supported_encryption_type(type:enc_type) == FALSE))
   return NULL;

 # (OPTIONAL) Kvno == 2
 kvno = der_parse_int (i:seq[1]);
 if (kvno && ((kvno != 2) && (kvno != 1)))
   return NULL;

 # encrypted data
 encrypted = der_parse_octet_string (string:seq[2]);
 if (!encrypted)
   return NULL;

 # We have enc-part in _encrypted[1] here.

 realm = der_parse_data(tag:0x1b, data:crealm);
 seq = der_parse_sequence (seq:cname, num:5, list:FALSE);
 if (isnull(seq))
   return NULL;
 seq = der_parse_sequence (seq:seq[1], num:5, list:TRUE);
 if (isnull(seq))
   return NULL;
 principal = der_parse_data(tag:0x1b, data:seq[1]);

 decrypted = kerberos_decrypt (key:password, type:raw_dword(d:8), data:encrypted, real_key:real_key, enc_type:enc_type, realm:realm, principal:principal);
 if (isnull(decrypted))
   return NULL;
 
 enc_part = der_decode (data:decrypted);
 if (isnull(enc_part) || ((enc_part[0] != 0x79) && (enc_part[0] != 0x7A)))
   return NULL;

 enc_part = der_parse_sequence (seq:enc_part[1], num:12, list:FALSE);
 if (isnull (enc_part))
   return NULL;

 enc_key = der_parse_sequence (seq:enc_part[0], num:2, list:FALSE);
 if (isnull (enc_key))
   return NULL;

 # We parse encryption key
 
 # Encryption type
 enc_type = der_parse_int (i:enc_key[0]);
 if (isnull (enc_type) || (supported_encryption_type(type:enc_type) == FALSE))
   return NULL;

 resp[4] = enc_type;

 # Encryption key
 enc_key = der_parse_octet_string (string:enc_key[1]);
 if (isnull (enc_key))
   return NULL;
 
 # We store the session key
 resp[1] = enc_key;
 
 return resp;
}


#---------------------------------------------------------#
# Function    : der_decode_asrep                          #
# Description : Return der decoded AP-REP                 #
#---------------------------------------------------------#

function der_decode_asrep (password, data)
{
 return der_decode_kdcrep (type:0x0B, password:password, data:data, real_key:FALSE);
}


#---------------------------------------------------------#
# Function    : der_decode_tgsrep                         #
# Description : Return der decoded TGS-REP                #
#---------------------------------------------------------#

function der_decode_tgsrep (session, data)
{
 return der_decode_kdcrep (type:0x0D, password:session[1], data:data, real_key:TRUE);
}


#---------------------------------------------------------#
# Function    : der_encode_apreq                          #
# Description : Return der encoded AP-REQ                 #
#---------------------------------------------------------#

function der_encode_apreq (session, req_body, type, _checksum, _seqnum)
{
 local_var list, options, encoded, authenticator, authenticators, checksum, auth, realm, principal, seq, cksum;

 authenticator = authenticators = checksum = NULL;

# checksum[0] = der_encode_int (i:-138);
# checksum[1] = der_encode (tag:0x04, data:rc4_hmac_checksum(key:session[1],type:raw_dword(d:6),data:req_body));
 
 realm = der_parse_data(tag:0x1b, data:session[2]);
 seq = der_parse_sequence (seq:session[3], num:5, list:FALSE);
 if (isnull(seq))
   return NULL;
 seq = der_parse_sequence (seq:seq[1], num:5, list:TRUE);
 if (isnull(seq))
   return NULL;
 principal = der_parse_data(tag:0x1b, data:seq[1]);

 options = der_encode (tag:0x03, data:raw_string (0x00,0x20,0x00,0x00,0x00));
 
 authenticator[0] = der_encode_int(i:5);
 authenticator[1] = session[2];
 authenticator[2] = session[3];

 if (!isnull(req_body))
 {
  cksum = kerberos_checksum(key:session[1],type:raw_dword(d:6),data:req_body,real_key:TRUE,realm:realm,principal:principal,enc_type:session[4]);

  checksum[0] = der_encode_int (i:get_checksum_type(enc_type:session[4]));
  checksum[1] = der_encode (tag:0x4, data:cksum);

  authenticator[3] = der_encode_sequence (seq:checksum);
 }
 else if (!isnull(_checksum))
  authenticator[3] = _checksum;
 else
  authenticator[3] = NULL;
 authenticator[4] = der_encode_int(i:0);
 authenticator[5] = der_encode_time (time:kerberostime());

 if (!isnull(_seqnum))
 {
  authenticator[6] = NULL;
  authenticator[7] = der_encode_int32 (i:_seqnum);
 }

 auth = der_encode_sequence (seq:authenticator);

 authenticators = der_encode_crypt (key:session[1], type:type, data:der_encode (tag:0x62, data:auth), real_key:TRUE, realm:realm, principal:principal, enc_type:session[4]);


 list = NULL;

 list[0] = der_encode_int(i:5); # Pvno = 5
 list[1] = der_encode_int(i:0x0E); # MSG-Type = AP-REQ
 list[2] = options;
 list[3] = session[0];
 list[4] = authenticators;

 encoded = der_encode_sequence (seq:list);

 return der_encode (tag:0x6E, data:encoded);
}


#---------------------------------------------------------#
# Function    : der_encode_tgsreq                         #
# Description : Return der encoded TGS-REQ                #
#---------------------------------------------------------#

function der_encode_tgsreq (session,name)
{
 local_var realm, req_body, encoded, padata, service, apreq;

 realm = der_decode (data:session[2]);
 service = der_encode_name (type:3, name1:"host", name2:name);  # Microsoft uses "cifs" for "host"
 req_body = der_encode_kdc_req_body (realm:realm[1], service:service);
 
 apreq = der_encode_apreq (session:session,req_body:req_body,type:7);
 padata = der_encode_padata (type:1, value:apreq);

 encoded = der_encode_kdcreq (pvno:5, msg_type:0x0C, list:padata, req_body:req_body);

 return der_encode (tag:0x6C, data:encoded);
}



#---------------------------------------------------------#
# Function    : der_encode_negtokeninit                   #
# Description : Return der encoded NegTokenInit           #
#---------------------------------------------------------#
#                                                         #
# NegTokenInit ::= SEQUENCE {                             #
#   mechTypes     [0]  MechTypeList  OPTIONAL,            #
#   reqFlags      [1]  ContextFlags  OPTIONAL,            #
#   mechToken     [2]  OCTET STRING  OPTIONAL,            #
#   mechListMIC   [3]  OCTET STRING  OPTIONAL             #
# }                                                       #
#                                                         #	    
#---------------------------------------------------------#

function der_encode_negtokeninit (mechtypes, reqflags, mechtoken, mechlistmic)
{
 local_var seq, encoded, list, negtokeninit, spnego_oid;

 encoded = list = NULL;
 
 if (mechtypes)
   list[0] = mechtypes;

 if (reqflags)
   list[1] = reqflags;

 if (mechtoken)
   list[2] = mechtoken;

 if (mechlistmic)
   list[3] = mechlistmic;

 seq = der_encode_sequence (seq:list);
  
 # NegTokenInit Tag = 0xA0
 negtokeninit = der_encode (tag:0xA0, data:seq);

 # SPNEGO OID 
 spnego_oid = der_encode_oid (oid:"1.3.6.1.5.5.2");

 # Application Constructed Object Tag = 0x60
 return der_encode (tag:0x60, data: spnego_oid + negtokeninit);
}


#---------------------------------------------------------#
# Function    : der_parse_spnego_init                     #
# Description : Return der decoded SPNEGO BLOB            #
#---------------------------------------------------------#

function der_parse_spnego_init (sdata)
{
 local_var tmp, data, oid, list, seq, mechtypes, mechseq, mechlistmic;
 local_var negtokeninit;

 data = der_parse_data (tag:0x60, data:sdata);
 if (isnull(data))
   return NULL;

 list = der_parse_list (list:data);
 if (isnull(list) || (list[0] != 2))
   return NULL;
 
 oid = der_parse_oid (oid:list[1]);
 if (!oid || (oid != "1.3.6.1.5.5.2"))
   return NULL;
 
 negtokeninit = NULL;
 negtokeninit[0] = negtokeninit[1] = negtokeninit[2] = negtokeninit[4] = NULL; 
 
 # negTokenInit
 data = der_parse_data (tag:0xA0, data:list[2]);
 if (data)
 {
  seq = der_parse_sequence (seq:data, num:4, list:FALSE);
  if (isnull(seq))
    return NULL;

  #mechType
  if (seq[0] != NULL)
  {
   mechtypes = der_parse_list_oid (list:seq[0]);
   if (!mechtypes)
     return NULL;

   negtokeninit[0] = mechtypes;
  }
 
  #mechListMIC
  if (seq[3] != NULL)
  {
   mechseq = der_parse_sequence (seq:seq[3], num:1, list:FALSE);
   if (isnull (mechseq))
     return NULL;
  
   tmp = der_decode (data:mechseq[0]);
   if (isnull(tmp) || (tmp[0] != 0x1B))
     return NULL;

   mechlistmic = tmp[1];

   negtokeninit[3] = mechlistmic;
  }
 }
 else
  return NULL;
  
 return negtokeninit;
}


#---------------------------------------------------------#
# Function    : der_parse_spnego_resp                     #
# Description : Return der decoded SPNEGO BLOB            #
#---------------------------------------------------------#

function der_parse_spnego_resp (sdata)
{
 local_var data, seq, negresult, supportedmech, responsetoken;
 local_var negtokentarg;
 
 negtokentarg = NULL;
 negtokentarg[0] = negtokentarg[1] = negtokentarg[2] = negtokentarg[3] = NULL;
 
 data = der_parse_data (tag:0xA1, data:sdata);
 if (isnull(data))
   return NULL;
  
 seq = der_parse_sequence (seq:data, num:4, list:FALSE);
 if (isnull(seq))
   return NULL;

 #negresult
 if (seq[0] != NULL)
 {
  negresult = der_parse_data (tag:0x0A,data:seq[0]);
  if (isnull (negresult))
    return NULL;

  negresult = ord(negresult[0]);

  negtokentarg[0] = negresult;
 }
 
 if (seq[1] != NULL)
 {
  supportedmech = der_parse_oid (oid:seq[1]);
  if (!supportedmech)
    return NULL;

  negtokentarg[1] = supportedmech;
 }
 
 if (seq[2] != NULL)
 {
  responsetoken = der_parse_data (tag:0x04, data:seq[2]);
  if (!responsetoken)
    return NULL;

  negtokentarg[2] = responsetoken;
 }
 
 return negtokentarg;
}


function acquired_ticket ()
{
 if (get_kb_item ("SMB/kerberos/tgs_ticket"))
   return 1;
 else
   return 0;
}


function save_tgs_session (session)
{
 set_kb_item (name:"SMB/kerberos/tgs_session_0", value:hexstr(session[0]));
 set_kb_item (name:"SMB/kerberos/tgs_session_1", value:hexstr(session[1]));
 set_kb_item (name:"SMB/kerberos/tgs_session_2", value:hexstr(session[2]));
 set_kb_item (name:"SMB/kerberos/tgs_session_3", value:hexstr(session[3]));
 set_kb_item (name:"SMB/kerberos/tgs_session_4", value:session[4]);
 set_kb_item (name:"SMB/kerberos/tgs_ticket", value:1);
}

function _hex2raw(s)
{
 local_var i, j, ret, l;

 s = chomp(s);	# remove trailing blanks, CR, LF...
 l = strlen(s);
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


function load_tgs_session ()
{
 local_var session;

 session[0] = _hex2raw(s:get_kb_item ("SMB/kerberos/tgs_session_0"));
 session[1] = _hex2raw(s:get_kb_item ("SMB/kerberos/tgs_session_1"));
 session[2] = _hex2raw(s:get_kb_item ("SMB/kerberos/tgs_session_2"));
 session[3] = _hex2raw(s:get_kb_item ("SMB/kerberos/tgs_session_3"));
 session[4] = get_kb_item ("SMB/kerberos/tgs_session_4");

 return session;
}


#---------------------------------------------------------#
# Function    : kerberos_securityblob                     #
# Description : Return kerberos/GSSAPI/SPNEGO blob        #
#---------------------------------------------------------#

function kerberos_securityblob (login,password,realm,host)
{
 local_var ret, mechtypes, mechtoken, apreq, soc2, pass, req, resp, session, i;

 # We only support Microsoft Kerberos
 # mechtypes = der_encode (tag:0x30, data:der_encode_oid (oid:"1.2.840.48018.1.2.2") + der_encode_oid (oid:"1.2.840.113554.1.2.2"));
 mechtypes = der_encode (tag:0x30, data:der_encode_oid (oid:"1.2.840.48018.1.2.2"));

 if (!acquired_ticket())
 {
  soc2 = open_sock_kdc ();
  if (isnull (soc2))
    return NULL;

  pass = NULL;
  for (i = 0; i < strlen (password); i++)
    pass += password[i] + raw_string(0x00);

  req = der_encode_asreq (principal:login, realm:realm, password:pass, enc_type:23);
  send (socket:soc2, data:req);

  resp = recv (socket:soc2, length:4096);
  if (!resp)
  {
   close (soc2);
   return NULL;
  }
  session = der_decode_asrep(password:pass, data:resp);
  if (isnull(session))
  {
   close (soc2);
   return NULL;
  }

  req = der_encode_tgsreq (session:session,name:host);
  send (socket:soc2, data:req);

  resp = recv (socket:soc2, length:4096);
  close (soc2);
  if (!resp)
    return NULL;
   
  session = der_decode_tgsrep(session:session, data:resp);
  if (isnull (session))
    return NULL;

  save_tgs_session(session:session);
 }
 else
 {
  session = load_tgs_session();
 }
  
 apreq = der_encode_apreq (session:session, type:11);
 
 mechtoken = der_encode_oid (oid:"1.2.840.113554.1.2.2") +
             raw_word (w:1)+
	     apreq;
 mechtoken = der_encode (tag:0x60, data:mechtoken);
 mechtoken = der_encode_octet_string (string:mechtoken);

 # MS KRB5 has no init flags and no mechListMIC
 ret = NULL;
 ret[0] = session[1];
 ret[1] = der_encode_negtokeninit (mechtypes:mechtypes, reqflags:NULL, mechtoken:mechtoken, mechlistmic:NULL);

 return ret;
}



#---------------------------------------------------------#
# Function    : check_kerberos_response                   #
# Description : Return 1 if trusted/accepted              #
#---------------------------------------------------------#

function check_kerberos_response (data, key, realm, principal)
{
 local_var negtokentarg, negresult, supportedmech, responsetoken, init, msg, challenge, kerberosblob, name;
 local_var list, oid, seq, kid, aprep, pvno, msg_type, enc_part, enc_type, encrypted, decrypted, enc_key, ret;

 negtokentarg = der_parse_spnego_resp (sdata:data);
 if (isnull (negtokentarg))
   return NULL;
 
 negresult = negtokentarg[0];
 if (negresult != 0) # Accept Complete
   return NULL;
 
 supportedmech = negtokentarg[1];
 
 if ("1.2.840.48018.1.2.2" >!< supportedmech)
   return NULL;
 
 responsetoken = negtokentarg[2];
 if (!responsetoken)
   return NULL;
 
 kerberosblob = der_parse_data (tag:0x60, data:responsetoken);
 if (isnull (kerberosblob))
   return NULL;

 list = der_parse_list (list:kerberosblob);
 if (isnull (list))
   return NULL;

 if (list[0] != 3)
   return NULL;

 oid = der_parse_oid (oid:list[1]);
 if (!oid || ("1.2.840.113554.1.2.2" >!< oid))
   return NULL;
 
 kid = list[2];
 if (ord(kid[0]) != 2) # AP-REP
   return NULL;
 
 aprep = der_parse_data (tag:0x6F, data:list[3]);
 if (isnull (aprep))
   return NULL;
 
 seq = der_parse_sequence (seq:aprep, num:4, list:FALSE);
 if (isnull (seq))
   return NULL;

 pvno = der_parse_int (i:seq[0]);
 if (isnull (pvno) || (pvno != 5))
   return NULL;
 
 msg_type = der_parse_int (i:seq[1]);
 if (isnull (msg_type) || (msg_type != 15)) # AP-REP
   return NULL;
 
 enc_part = der_parse_sequence (seq:seq[2], num:3, list:NULL);
 if (isnull (enc_part))
   return NULL;

 enc_type = der_parse_int (i:enc_part[0]);
 if (isnull (enc_type) || (supported_encryption_type(type:enc_type) == FALSE))
   return NULL;

 encrypted = der_parse_octet_string (string:enc_part[2]);
 if (isnull (encrypted))
   return NULL;
 
 decrypted = kerberos_decrypt (key:key, type:raw_dword(d:12), data:encrypted, real_key:TRUE, enc_type:enc_type, realm:realm, principal:name);
 if (isnull (decrypted))
   return NULL;

 # we need to extract the subkey if present for SMB Signing
 enc_part = der_parse_data (tag:0x7b, data:decrypted);
 if (isnull (enc_part))
   return NULL;

 seq = der_parse_sequence (seq:enc_part, num:4, list:NULL);
 if (isnull (seq))
   return NULL;
 

 ret = NULL;
 ret [0] = 0;

 if (seq[2] != NULL)
 {
  seq = der_parse_sequence (seq:seq[2], num:2, list:NULL);
  if (isnull (seq))
    return NULL;

  enc_type = der_parse_int (i:seq[0]);
  if (isnull (enc_type) || (supported_encryption_type(type:enc_type) == FALSE))
    return NULL;
  
  enc_key = der_parse_octet_string (string:seq[1]);
  if (isnull (enc_key))
   return NULL;

  ret[0] = 1;
  ret[1] = enc_key;
 }

 return ret;
}





#---------------------------------------------------------#
# Function    : ntlmssp_negotiate_securityblob            #
# Description : Return NTLMSSP_NEGOCIATE blob             #
#---------------------------------------------------------#

function ntlmssp_negotiate_securityblob ()
{
 local_var mechtypes, mechtoken, ntlmssp, offset;

 mechtypes = der_encode (tag:0x30, data:der_encode_oid (oid:"1.3.6.1.4.1.311.2.2.10"));
 
 ntlmssp = "NTLMSSP" + raw_string (0x00);
 ntlmssp += raw_dword (d:1); # NTLMSSP_NEGOTIATE
 ntlmssp += raw_dword (d:NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_NTLM2);  # Flags
 ntlmssp += ntlmssp_data (data:NULL,offset:0); # workstation domain NULL
 ntlmssp += ntlmssp_data (data:NULL,offset:0); # workstation name NULL
 
 # Version 1.0
 ntlmssp += raw_byte (b:1) + raw_byte (b:0);
 # Version Number = 0
 ntlmssp += raw_word (w:0);

 # Unknown value
 ntlmssp += raw_string (0x00,0x00,0x00,0x0F);

 mechtoken = der_encode_octet_string (string:ntlmssp);
 
 return der_encode_negtokeninit (mechtypes:mechtypes, reqflags:NULL, mechtoken:mechtoken, mechlistmic:NULL);
}



#---------------------------------------------------------#
# Function    : ntlmssp_parse_challenge                   #
# Description : Return NTLM challenge                     #
#---------------------------------------------------------#

function ntlmssp_parse_challenge (data)
{
 local_var negtokentarg, negresult, supportedmech, responsetoken, init, msg, challenge, d_len, offset, domain, ret;
 
 negtokentarg = der_parse_spnego_resp (sdata:data);
 if (isnull (negtokentarg))
   return NULL;
 
 negresult = negtokentarg[0];
 if (negresult != 1) # Accept Incomplete
   return NULL;
 
 supportedmech = negtokentarg[1];
 
 if ("1.3.6.1.4.1.311.2.2.10" >!< supportedmech)
   return NULL;
 
 responsetoken = negtokentarg[2];
 if (!responsetoken)
   return NULL;
 
 if (strlen(responsetoken) < 40)
   return NULL;

 init = substr (responsetoken, 0, 7);
 if ("NTLMSSP" >!< init)
   return NULL;
 
 msg = substr (responsetoken, 8, 11);
 if ("02000000" >!< hexstr(msg)) # NTLMSSP_CHALLENGE
   return NULL;

 d_len = get_word (blob:responsetoken, pos:12);
 offset = get_dword (blob:responsetoken, pos:16);

 domain = substr (responsetoken, offset, offset+d_len-1);

 challenge = substr (responsetoken, 24, 31);

 ret[0] = challenge;
 ret[1] = domain;

 return ret;
}


#---------------------------------------------------------#
# Function    : ntlmssp_parse_response                    #
# Description : Return NTLM Result                        #
#---------------------------------------------------------#

function ntlmssp_parse_response (data)
{

 local_var negtokentarg, negresult;
 
 negtokentarg = der_parse_spnego_resp (sdata:data);
 if (isnull (negtokentarg))
   return NULL;
 
 negresult = negtokentarg[0];
 return negresult;
}



#---------------------------------------------------------#
# Function    : ntlmssp_data                              #
# Description : Return NTLMSSP data                       #
#               word  data_len                            #
#               word  data_len                            #
#		dword offset_data                         #
#---------------------------------------------------------#

function ntlmssp_data (data,offset)
{
 return raw_word (w:strlen(data)) + raw_word (w:strlen(data)) + raw_dword (d:offset);
}


#---------------------------------------------------------#
# Function    : ntlmssp_auth_securityblob                 #
# Description : Return NTLMSSP_AUTH blob                  #
#---------------------------------------------------------#

function ntlmssp_auth_securityblob (password,login,domain,challenge)
{
 local_var ntlmssp,nt,response,mechtoken,responsetoken;
 local_var hostname,sessionkey,lm,offset,key,ret;

 sessionkey = lm = nt = NULL;
 hostname = domain;

 # Systems with Extended Security Authentication support NTLMv2 so NTLMv1 is useless here (?) 

 if (login)
 {
  response = LMv2_Response (password:password, login:login, domain:domain, challenge:challenge);
  lm = response[0];
  key = response[1];
 }
 else
 {
  lm = raw_string (0x00);
 }

 #response = NTLM_Response (password:password, challenge:challenge);
 #nt = response[0];

 offset = 0x48; # First text;
 
 ntlmssp = "NTLMSSP" + raw_string (0x00);
 ntlmssp += raw_dword (d:3); # NTLMSSP_AUTH
 
 # Lan Manager response = NULL
 ntlmssp += ntlmssp_data (data:lm,offset:offset);
 offset += strlen (lm);

 # NTLM Response
 ntlmssp += ntlmssp_data (data:nt,offset:offset);
 offset += strlen(nt);

 # Domain name = NULL
 ntlmssp += ntlmssp_data (data:domain, offset:offset);
 offset += strlen (domain);
 
 # User name
 ntlmssp += ntlmssp_data (data:login, offset:offset);
 offset += strlen (login);

 # Host name = NULL
 ntlmssp += ntlmssp_data (data:hostname, offset:offset);
 offset += strlen (hostname);
 
 # Session Key = NULL
 ntlmssp += ntlmssp_data (data:sessionkey, offset:offset);
 offset += strlen (sessionkey);
 
 ntlmssp += raw_dword (d:NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_NTLM2); # Flags
 # Version 1.0
 ntlmssp += raw_byte (b:1) + raw_byte (b:0);
 # Version Number = 0
 ntlmssp += raw_word (w:0);

 # Unknown value
 ntlmssp += raw_string (0x00,0x00,0x00,0x0F);

 ntlmssp += lm + nt + domain + login + hostname + sessionkey; 

 ntlmssp = der_encode_octet_string (string:ntlmssp);
 responsetoken = der_encode (tag:0xA2, data:ntlmssp);
 responsetoken = der_encode_list (list:responsetoken);

 ret[0] = key;
 ret[1] = der_encode (tag:0xA1, data:responsetoken); 
 return ret;
}


#---------------------------------------------------------#
# Function    : kerberos_ssh                              #
# Description : Return kerberos blob                      #
#---------------------------------------------------------#

function kerberos_ssh (login,password,realm,host,seqnum)
{
 local_var ret, soc2, resp, rep, req, cksum, checksum, apreq, innercontexttoken, initialcontexttoken, session;

 soc2 = open_sock_kdc ();
 if (isnull (soc2))
   return NULL;

 req = der_encode_asreq (principal:login, realm:realm, password:password, enc_type:3);
 send (socket:soc2, data:req);

 resp = recv (socket:soc2, length:4096);
 if (!resp)
 {
   close (soc2);
   return NULL;
 }
 rep = der_decode_asrep(password:password, data:resp);
 session = rep;
 if (!resp)
 {
   close (soc2);
   return NULL;
 }

 req = der_encode_tgsreq (session:session,name:host);
 send (socket:soc2, data:req);

 resp = recv (socket:soc2, length:4096);
 close (soc2);
 if (!resp)
   return NULL;
   
 rep = der_decode_tgsrep(session:session, data:resp);
 session = rep;
 if (isnull (rep))
   return NULL;
   
 cksum = raw_dword (d:16) + # bnd length
         crap (data:raw_string(0),length:16) + #bnd
         raw_dword (d:32|2) + # flags
         
 checksum = NULL;
 checksum[0] = der_encode_int32 (i:0x8003);
 checksum[1] = der_encode (tag:0x04, data:cksum);

 apreq = der_encode_apreq(session:session, type:11, _checksum:der_encode_sequence (seq:checksum), _seqnum:seqnum);

 innercontexttoken = raw_string(0x01,0x00) + apreq;
 initialcontexttoken = der_encode_oid(oid:"1.2.840.113554.1.2.2")+innercontexttoken;

 ret = NULL;
 ret[0] = session[1];
 ret[1] = der_encode (tag:0x60, data:initialcontexttoken);

 return ret;
}


#---------------------------------------------------------#
# Function    : gssapi_ssh_get_mic                        #
# Description : Return gssapi mic                         #
#---------------------------------------------------------#

function gssapi_ssh_get_mic (data, key, seqnum)
{
 local_var hash, des_cksum, seq_num, crypted, mic;

 hash = MD5 ( raw_string(0x01,0x01,0x00,0x00,0xFF,0xFF,0xFF,0xFF) +
               data );

 des_cksum = des_cbc_checksum (key:key,data:hash,iv:raw_string(0,0,0,0,0,0,0,0));

 seq_num = raw_dword (d:seqnum) + raw_dword (d:0);

 crypted = des_cbc_encrypt (data:seq_num, key:key, iv:des_cksum, encrypt:1);

 mic = der_encode (tag:0x60, data:der_encode_oid(oid:"1.2.840.113554.1.2.2") + raw_string (0x01,0x01,0x00,0x00,0xFF,0xFF,0xFF,0xFF) + crypted + des_cksum);

 return mic;
}



#---------------------------------------------------------#
# Function    : check_gssapi_token                        #
# Description : Return 1 if trusted/accepted              #
#---------------------------------------------------------#

function check_gssapi_token (data, key, realm, principal)
{
 local_var list, oid, seq, kid, aprep, pvno, msg_type, enc_part, enc_type, encrypted, decrypted, enc_key, kerberosblob, ret;

  
 kerberosblob = der_parse_data (tag:0x60, data:data);
 if (isnull (kerberosblob) || (strlen(kerberosblob)<14))
   return NULL;

 list = NULL;
 list[1] = substr(kerberosblob,0,10);
 list[2] = substr(kerberosblob,11,12);
 list[3] = substr(kerberosblob,13,strlen(kerberosblob)-1);

 oid = der_parse_oid (oid:list[1]);
 if (!oid || ("1.2.840.113554.1.2.2" >!< oid))
   return NULL;
 
 kid = list[2];
 if (ord(kid[0]) != 2) # AP-REP
   return NULL;
 
 aprep = der_parse_data (tag:0x6F, data:list[3]);
 if (isnull (aprep))
   return NULL;
 
 seq = der_parse_sequence (seq:aprep, num:4, list:FALSE);
 if (isnull (seq))
   return NULL;

 pvno = der_parse_int (i:seq[0]);
 if (isnull (pvno) || (pvno != 5))
   return NULL;
 
 msg_type = der_parse_int (i:seq[1]);
 if (isnull (msg_type) || (msg_type != 15)) # AP-REP
   return NULL;
 
 enc_part = der_parse_sequence (seq:seq[2], num:3, list:NULL);
 if (isnull (enc_part))
   return NULL;

 enc_type = der_parse_int (i:enc_part[0]);
 if (isnull (enc_type) || (supported_encryption_type(type:enc_type) == FALSE))
   return NULL;

 encrypted = der_parse_octet_string (string:enc_part[2]);
 if (isnull (encrypted))
   return NULL;
 
 decrypted = kerberos_decrypt (key:key, type:raw_dword(d:12), data:encrypted, real_key:TRUE, enc_type:enc_type, realm:realm, principal:principal);
 if (isnull (decrypted))
   return NULL;

 # we need to extract the subkey if present for SMB Signing
 enc_part = der_parse_data (tag:0x7b, data:decrypted);
 if (isnull (enc_part))
   return NULL;

 seq = der_parse_sequence (seq:enc_part, num:4, list:NULL);
 if (isnull (seq))
   return NULL;
 

 ret = NULL;
 ret [0] = 0;

 if (seq[2] != NULL)
 {
  seq = der_parse_sequence (seq:seq[2], num:2, list:NULL);
  if (isnull (seq))
    return NULL;

  enc_type = der_parse_int (i:seq[0]);
  if (isnull (enc_type) || (supported_encryption_type(type:enc_type) == FALSE))
    return NULL;
  
  enc_key = der_parse_octet_string (string:seq[1]);
  if (isnull (enc_key))
   return NULL;

  ret[0] = 1;
  ret[1] = enc_key;
 }

 return ret;
}

