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
#
# @NOGPL@
#
# snmp_func.inc 
# $Revision: 1.8 $
#

global_var snmp_request_id, SNMP_VERSION, end_mib;

snmp_request_id = 0;
end_mib = FALSE;

SNMP_VERSION = get_kb_item ("SNMP/version");
if (isnull(SNMP_VERSION))
  SNMP_VERSION = 0; # snmpv1

function init_snmp ()
{
 end_mib = FALSE;
}


#---------------------------------------------------------#
# Function    : ber_length                                #
# Description : return raw ber length of data             #
#---------------------------------------------------------#

function ber_length (data)
{
 local_var tmp, length, len;

 length = NULL;
 len = strlen (data);

 if (len == 0)
   return raw_string (0);

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
# Function    : ber_encode                                #
# Description : Return ber encoded data                   #
#---------------------------------------------------------#

function ber_encode (tag,data)
{
 return raw_string (tag) + ber_length(data:data) + data;
}


#---------------------------------------------------------#
# Function    : ber_put_int                               #
# Description : Return ber encoded INTEGER                #
#---------------------------------------------------------#

function ber_put_int (i)
{
 local_var val,j,tmp;

 if (isnull (i))
   return NULL;

 val[0] = i & 255;
 val[1] = (i>>8)  & 255;
 val[2] = (i>>16) & 255;
 val[3] = (i>>24) & 255;

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
 
 return ber_encode (tag:0x02, data:tmp);
}


#---------------------------------------------------------#
# Function    : ber_put_octet_string                      #
# Description : Return ber encoded OCTET STRING           #
#---------------------------------------------------------#

function ber_put_octet_string (string)
{
 return ber_encode (tag:0x04, data:string);
}


#---------------------------------------------------------#
# Function    : ber_put_get_pdu                           #
# Description : Return ber encoded GetRequestPDU          #
#---------------------------------------------------------#

function ber_put_get_pdu (pdu)
{
 return ber_encode (tag:0xA0, data:pdu);
}


#---------------------------------------------------------#
# Function    : ber_put_get_next_pdu                      #
# Description : Return ber encoded GetRequestNextPDU      #
#---------------------------------------------------------#

function ber_put_get_next_pdu (pdu)
{
 return ber_encode (tag:0xA1, data:pdu);
}


#---------------------------------------------------------#
# Function    : ber_put_null                              #
# Description : Return ber encoded NULL                   #
#---------------------------------------------------------#

function ber_put_null ()
{
 return ber_encode (tag:0x05, data:NULL);
}


#---------------------------------------------------------#
# Function    : ber_put_oid                               #
# Description : Return ber encoded OID (string)           #
#               ex: "1.2.840.113554.1.2.2"                #
#---------------------------------------------------------#

function ber_put_oid (oid)
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
 return ber_encode (tag:0x06, data:encoded);
}


#---------------------------------------------------------#
# Function    : ber_put_sequence                          #
# Description : Return ber encoded SEQUENCE               #
#---------------------------------------------------------#

function ber_put_sequence (seq)
{
 local_var encoded, max, i, j, val;

 max = max_index (seq);

 encoded = NULL;
 
 for (j=0; j < max; j++)
 {
  val = seq[j];
  if (!isnull(val))
  {
    encoded += val;
  }
 }

 # SEQUENCE Tag = 0x30
 return ber_encode (tag:0x30, data:encoded); 
}


function integer (i)
{
 local_var j,k,len;

 j = 0;
 len = strlen (i);

 for (k=0; k < len; k++)
 {
  j = j * 256 + ord(i[k]);
 }
 
 return j;
}


#---------------------------------------------------------#
# Function    : ber_decode                                #
# Description : Return ber decoded data                   #
#               [0] = code                                #
#               [1] = data                                #
#               [2] = next pos in buffer                  #
#---------------------------------------------------------#

function ber_decode (data, pos)
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
# Function    : ber_decode_oid                            #
# Description : Return OID (string)                       #
#               ex: "1.2.840.113554.1.2.2"                #
#---------------------------------------------------------#

function ber_decode_oid (oid)
{
 local_var soid, i, val, len;

 if (strlen (oid) < 1)
   return NULL;

 soid = string (ord (oid[0]) / 40, ".", ord (oid[0]) % 40);

 len = strlen (oid);

 for (i = 1; i < len; i++)
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
# Function    : ber_get_data                              #
# Description : Return ber decoded data                   #
#---------------------------------------------------------#

function ber_get_data (tag,data)
{
 local_var tmp;

 tmp = ber_decode (data:data);
 if (isnull (tmp) || (tmp[0] != tag))
   return NULL;

 return tmp[1];
}


#---------------------------------------------------------#
# Function    : ber_get_sequence                          #
# Description : Return der decoded sequence               #
#---------------------------------------------------------#

function ber_get_sequence (seq)
{
 local_var tmp,pos,i,ret,list, len;

 if (!seq)
   return NULL;

 list = ber_decode (data:seq);
 if (isnull(list) || (list[0] != 0x30))
   return NULL;

 list = list[1];
 
 tmp = NULL;
 tmp[0] = 0;
 
 pos = 0;
 i = 1;
 len = strlen (list);

 while (pos < len)
 {
  ret = ber_decode (data:list,pos:pos);
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
# Function    : ber_response_pdu                          #
# Description : Return ber decoded response_pdu           #
#---------------------------------------------------------#

function ber_get_response_pdu (pdu)
{
 local_var tmp,pos,i,ret,list, len;

 if (!pdu)
   return NULL;

 list = ber_decode (data:pdu);
 if (isnull(list) || ((list[0] != 0xA2) && (list[0] != 0xA1)) )
   return NULL;

 list = list[1];
 
 tmp = NULL;
 tmp[0] = 0;
 
 pos = 0;
 i = 1;
 len = strlen (list);

 while (pos < len)
 {
  ret = ber_decode (data:list,pos:pos);
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
# Function    : ber_get_int                               #
# Description : Return ber decoded integer                #
#---------------------------------------------------------#

function ber_get_int (i)
{
 local_var tmp;

 tmp = ber_get_data (tag:0x02, data:i);
 if (isnull(tmp))
   return NULL;

 tmp = integer (i:tmp);
 if (isnull(tmp))
   return NULL;

 return tmp;
}


#---------------------------------------------------------#
# Function    : ber_get_timeticks                         #
# Description : Return ber decoded time                   #
#---------------------------------------------------------#

function ber_get_timeticks (time)
{
 local_var tmp, ms, s, m, h, d;

 tmp = ber_get_data (tag:0x43, data:time);
 if (isnull(tmp))
   return NULL;

 if ((strlen(tmp) > 4) || (strlen(tmp) == 4 && ord(tmp[0]) > 0x80))
 {
  return string ("Time is too big to be decoded : 0x", hexstr(tmp), " ms");
 }

 tmp = integer (i:tmp);
 if (isnull(tmp))
   return NULL;

 # convert to sec
 tmp = tmp / 100;
 s = tmp % 60;
 tmp = tmp / 60;
 m = tmp % 60;
 tmp = tmp / 60;
 h = tmp % 24;
 d = tmp / 24;

 return string (d, "d ",h,"h ",m, "m ", s, "s");
}


#---------------------------------------------------------#
# Function    : ber_get_octet_string                      #
# Description : Return ber decoded octet string           #
#---------------------------------------------------------#

function ber_get_octet_string (string)
{
 return ber_get_data (tag:0x04, data:string);
}


#---------------------------------------------------------#
# Function    : ber_get_oid                               #
# Description : Return ber decoded oid                    #
#---------------------------------------------------------#

function ber_get_oid (oid)
{
 local_var tmp;

 tmp = ber_get_data (tag:0x06, data:oid);
 if (!tmp)
   return NULL;

 tmp = ber_decode_oid (oid:tmp);
 if (!tmp)
   return NULL;

 return tmp;
}


#---------------------------------------------------------#
# Function    : snmp_extract_reply                        #
# Description : Return ber decoded snmp reply value       #
#---------------------------------------------------------#

function snmp_extract_reply (rep)
{
 if (strlen(rep) < 2)
   return NULL;

 if (ord(rep[0]) == 0x02)
   return ber_get_int (i:rep);

 if (ord(rep[0]) == 0x04)
   return ber_get_octet_string (string:rep);

 if (ord(rep[0]) == 0x06)
   return ber_get_oid (oid:rep);

 if (ord(rep[0]) == 0x82)
 {
  end_mib = TRUE;
  return NULL;
 }

 if (ord(rep[0]) == 0x43)
   return ber_get_timeticks (time:rep);

 return NULL;
}


#---------------------------------------------------------#
# Function    : snmp_reply                                #
# Description : Return ber decoded snmp reply value       #
#---------------------------------------------------------#

function snmp_reply (socket, timeout)
{
 local_var seq, res, pdu, error, oid, ret, rep, id, cmpt, vers;

 cmpt = 5;

 while (cmpt)
 {
  rep = recv(socket:socket, length:4096, timeout:timeout);
  if (!rep)
    return NULL;

  # First decode snmp reply (sequence)
  seq = ber_get_sequence (seq:rep);
  if (isnull(seq) || (seq[0] != 3))
    return NULL;

  # Check if version is 1 (0)
  vers = ber_get_int (i:seq[1]);
  if (isnull(vers) || vers != SNMP_VERSION)
    return NULL;

  # Check if Response PDU is 2
  pdu = ber_get_response_pdu (pdu:seq[3]);
  if (isnull(pdu) || (pdu[0] != 4))
    return NULL;

  id = ber_get_int (i:pdu[1]);
  if (!isnull(id) && id == (snmp_request_id - 1))
  {
   # Check if Error == NO ERROR
   error = ber_get_int (i:pdu[2]);
   if (isnull(error) || (error != 0))
     return NULL;

   # Extract response
   seq = ber_get_sequence (seq:pdu[4]);
   if (isnull(seq) || (seq[0] != 1))
     return NULL;
 
   seq = ber_get_sequence (seq:seq[1]);
   if (isnull(seq) || (seq[0] != 2))
     return NULL;

   oid = ber_get_oid (oid:seq[1]);
   res = snmp_extract_reply (rep:seq[2]);

   if (isnull(oid))
     return NULL;

   ret = make_list();
   ret[0] = oid;
   ret[1] = res;

   return ret;
  }

  cmpt--;
 }
}


#---------------------------------------------------------#
# Function    : snmp_request                              #
# Description : Do an snmp request and return reply       #
#---------------------------------------------------------#

function snmp_request (socket, community, oid)
{
 local_var req, rep, seq, request;

 seq = make_list(
                 ber_put_oid (oid:oid),
                 ber_put_null ()
                );

 seq = make_list(
                 ber_put_sequence(seq:seq)
                );

 request =        
       ber_put_int (i:snmp_request_id)          + # Request Id
       ber_put_int (i:0)                        + # Error Status: NO ERROR (0)
       ber_put_int (i:0)                        + # Error Index (0)
       ber_put_sequence (seq:seq);                # Object Identifier

req =  ber_put_int (i:SNMP_VERSION)             + # version
       ber_put_octet_string (string:community)  + # community string
       ber_put_get_pdu (pdu:request);             # PDU type

 req = ber_put_sequence (seq:make_list(req));

 snmp_request_id += 1;

 send (socket:socket, data:req);
 rep = snmp_reply (socket:socket);

 if ( isnull(rep) )
	return NULL;
 else
	return rep[1];
}


#---------------------------------------------------------#
# Function    : snmp_request_next                         #
# Description : Do an snmp request_next and return reply  #
#---------------------------------------------------------#

function snmp_request_next (socket, community, oid, timeout)
{
 local_var req, rep, seq, request, ret;

 seq = make_list(
                 ber_put_oid (oid:oid),
                 ber_put_null ()
                );

 seq = make_list(
                 ber_put_sequence(seq:seq)
                );

 request =        
       ber_put_int (i:snmp_request_id)          + # Request Id
       ber_put_int (i:0)                        + # Error Status: NO ERROR (0)
       ber_put_int (i:0)                        + # Error Index (0)
       ber_put_sequence (seq:seq);                # Object Identifier

req =  ber_put_int (i:SNMP_VERSION)             + # version
       ber_put_octet_string (string:community)  + # community string
       ber_put_get_next_pdu (pdu:request);        # PDU type

 req = ber_put_sequence (seq:make_list(req));

 snmp_request_id += 1;

 send (socket:socket, data:req);

 ret = snmp_reply (socket:socket, timeout:timeout);

 if (end_mib)
   return NULL;

 return ret;
}


#---------------------------------------------------------#
# Function    : scan_snmp_string                          #
# Description : do a snmp string scan with get_next_pdu   #
#---------------------------------------------------------#

function scan_snmp_string(socket, community, oid)
{
 local_var soid, list, port;

 list = NULL;
 soid = oid;

 while(1)
 {
  port = snmp_request_next (socket:socket, community:community, oid:soid);
  if (!isnull(port) && egrep (pattern:string("^",oid,"\\."), string:port[0]))
  {
   list = string (list, port[1], "\n");
   soid = port[0];
  }
  else
    break;
 }

 return list;
}


#---------------------------------------------------------#
# Function    : is_valid_snmp_product                     #
# Description : checks if the product oid is from the same#
#               manufacturer                              #
#---------------------------------------------------------#

function is_valid_snmp_product(manufacturer, oid)
{
 if (egrep(pattern:string("^",manufacturer,"\\..*"), string:oid))
   return TRUE;

 return FALSE;
}
