# -*- Fundamental -*-
#
# 
# (C) 2006 Tenable Network Security
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
# smb_internals.inc 
# $Revision: 1.5 $
#

# GLOBAL VAR : Session. Can be used as arg later.
global_var Session, previous_hash;


function kb_smb_name()
{
 local_var ret;
 ret = get_kb_item("SMB/name");
 if ( ret ) 
	return string(ret);
 else
	return get_host_ip();
}

function kb_smb_domain()
{
 return string(get_kb_item("SMB/domain"));
}

function kb_smb_login()
{
 return string(get_kb_item("SMB/login"));
}

function kb_smb_password()
{
 return string(get_kb_item("SMB/password"));
}

function kb_smb_transport()
{
 local_var r;
 r = get_kb_item("SMB/transport");
 if ( r ) return int(r);
 else return 445;
}




#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#



#---------------------------------------------------------#
# Function    : get_string                                #
# Description : Extract a null terminated string          #
#---------------------------------------------------------#

function get_string (blob, pos, _type)
{
 local_var string, i, unicode, len;

 if (isnull (_type))
   unicode = session_is_unicode();
 else
   unicode = _type;

 string = NULL;
 i = pos;
 len = strlen(blob);

 while (i < len)
 {
  if (unicode == 1)
  {
   if ((blob[i] == '\0') && (blob[i+1] == '\0'))
    return unicode2ascii (string:string); 
   string += blob[i] + blob[i+1];
   i += 2;
  }
  else
  {
   if (blob[i] == '\0')
     return string;
   string += blob[i];
   i++;
  }
 }
}


#---------------------------------------------------------#
# Function    : get_string2                               #
# Description : Extract a non null terminated string      #
#---------------------------------------------------------#

function get_string2 (blob, pos, len, _type)
{
 local_var string, unicode;

 if (isnull (_type))
   unicode = session_is_unicode();
 else
   unicode = _type;

 string = NULL;

 if (pos+len > strlen(blob))
   return NULL;

 string = substr (blob, pos, pos+len-1);
 if (unicode == 1)
   return unicode2ascii (string:string); 
 else
   return string;
}


#---------------------------------------------------------#
# Function    : null_length                               #
# Description : return size of null end char              #
#---------------------------------------------------------#

function null_length ()
{
 if (session_is_unicode() == 1)
   return 2;
 else
   return 1;
}


#---------------------------------------------------------#
# Function    : dos_status                                #
# Description : Return DOS_status code                    #
#---------------------------------------------------------#

function dos_status (ErrorClass, ErrorCode)
{
 return  raw_byte (b:ErrorClass) +
         raw_byte (b:0) +
         raw_word (w:ErrorCode);
}


#---------------------------------------------------------#
# Function    : nt_status                                 #
# Description : Return NT_status code                     #
#---------------------------------------------------------#

function nt_status (Status)
{
 return raw_dword (d:Status);
}


#---------------------------------------------------------#
# Function    : ascii                                     #
# Description : Convert string to ASCII string (NULL end) #
#---------------------------------------------------------#

function ascii (string)
{
 return string + raw_byte (b:0);
}



#---------------------------------------------------------#
# Function    : unicode                                   #
# Description : Convert ASCII string to unicode           #
#---------------------------------------------------------#

function unicode (string)
{
 local_var ustring, i, len, end;

 ustring = NULL;

 len = strlen(string);
 end = raw_byte (b:0);

 for (i=0; i<len; i++)
 {
   ustring += string[i] + end;
 }

 return ustring;
}


#---------------------------------------------------------#
# Function    : unicode2ascii                             #
# Description : Convert unicode string to ascii           #
#---------------------------------------------------------#

function unicode2ascii (string)
{
 local_var astring, i, len;

 astring = NULL;

 len = strlen (string);
 for (i=0; i<len; i+=2)
 {
   astring += string[i];
 }

 while (astring && (astring[strlen(astring)-1] == '\0'))
   astring = substr(astring, 0, strlen(astring)-2);

 return astring;
}


#---------------------------------------------------------#
# Function    : isUnicode                                 #
# Description : Return 1 if string is in real unicode     #
#---------------------------------------------------------#

function isUnicode (string)
{
 # Unicode are not supported yet in nessus
 return 0;
}


#---------------------------------------------------------#
# Function    : cstring                                   #
# Description : Convert string to ascii or unicode        #
#               If null is set, null end char is not      #
#               added                                     #
#---------------------------------------------------------#

function cstring (string, _null)
{
 local_var astring, ustring, i, sUnicode;

 sUnicode = session_is_unicode();

 # If the string is not in real unicode
 if (isUnicode (string:string) == 0)
 {
  if ( (!string && (_null == 1)) || ((sUnicode == 0) && (_null == 1)) )
    return string;
   
  if (sUnicode == 1)
  {
   if (_null == 1)
     return unicode (string:string);
   else
     return unicode (string:ascii(string:string));
  }
  else
    return ascii (string:string);
 }
 else
 {
  # sUnicode must be set to 1 in this case.
  if (_null == 1)
    return string;
  else
    return string + raw_string (0x00,0x00);
 }
}


function convert_time_to_sec (time, no_zero)
{
 local_var high, low, add, tmp, tmp2, i, j, val;

 high = get_dword (blob:time, pos:4);
 low = get_dword (blob:time, pos:0);

 if ((low == 0) && (high == 0x80000000))
   return -1;

 if (isnull(no_zero) || (no_zero == FALSE))
 {
  # 0 - time
  if (low != 0)
    high = 0 - (high+1);
  else
    high = 0 - high;

  low = 0 - low;
 }

 tmp = raw_dword(d:low)+raw_dword(d:high);

 for (i=0; i<7; i++)
 {
  val = 0;
  tmp2 = NULL;
  for (j=0; j<8; j++)
  {
   tmp2 = raw_string((ord(tmp[7-j])+val*256)/2) + tmp2;
   val = (ord(tmp[7-j])+val*256)%2;
  }
  tmp = tmp2;
 }

 for (i=0; i<7; i++)
 {
  val = 0;
  tmp2 = NULL;
  for (j=0; j<8; j++)
  {
   tmp2 = raw_string((ord(tmp[7-j])+val*256)/5) + tmp2;
   val = (ord(tmp[7-j])+val*256)%5;
  }
  tmp = tmp2;
 }

 return get_dword(blob:tmp, pos:0);
}




#==================================================================#
# Section 2. Session functions                                     #
#==================================================================#


# Session structure (array):
#
# DWORD Socket;
# DWORD Timeout;
# WORD  Uid;
# WORD  Tid;
# WORD  Pid;
# WORD  Mid;
# BYTE  Unicode;
# DWORD cMaxBufferSize;
# DWORD SequenceNumber;
# BYTE  MAC_Key[];
# BYTE  Flags;
# WORD  Flags2;

function session_init (socket,timeout,login,domain,password,hostname)
{
 local_var session, host;

 Session[0] = socket;
 
 if (!isnull (timeout))
   Session[1] = timeout;
 else
   Session[1] = 15;

 if (isnull (hostname))
   host = NULL;
 else
 {
   host = hostname;
   while (host[strlen(host)-1] == ' ')
     host = substr(host,0,strlen(host)-2);
 }

 Session[2] = 0; # Uid
 Session[3] = 0; # Tid
 Session[4] = rand(); # Pid
 Session[5] = 0; # Mid
 Session[6] = 0; # Unicode
 Session[7] = 0x4400; # Client Max Buffer Size
 Session[8] = 0; # SequenceNumber
 Session[9] = NULL; # MAC_Key
 Session[10] = SMB_FLAGS_CANONICAL_PATHNAMES | SMB_FLAGS_CASELESS_PATHNAMES;
 Session[11] = SMB_FLAGS2_KNOWS_LONG_NAMES | SMB_FLAGS2_32BIT_STATUS | SMB_FLAGS2_EAS;
 Session[12] = host;
 Session[13] = 0;
 Session[14] = 0; # GUEST
 Session[15] = 0; # cid
 Session[16] = 0; # Server Max buff size
 Session[17] = NULL; # Os
 Session[18] = NULL; # Lan Manager
 Session[19] = NULL; # Domain
}


function session_get_socket ()
{
 return Session[0];
}


function session_set_socket (socket)
{
 Session[0] = socket;
}


function session_get_timeout ()
{
 return Session[1];
}


function session_set_timeout (timeout)
{
 Session[1] = timeout;
}


function session_get_uid ()
{
 return Session[2];
}


function session_set_uid (uid)
{
 Session[2] = uid;
}


function session_get_tid ()
{
 return Session[3];
}


function session_set_tid (tid)
{
 Session[3] = tid;
}


function session_get_pid ()
{
 return Session[4];
}


function session_set_pid (pid)
{
 Session[4] = pid;
}


function session_get_mid ()
{
 local_var mid;

 mid = Session[5];
 Session[5] = mid + 64;

 return mid;
}


function session_set_mid (mid)
{
 Session[5] = mid;
}


function session_is_unicode ()
{
 return Session[6];
}


function session_set_unicode (unicode)
{
 if (unicode == 1)
   session_add_flags2 (flag:SMB_FLAGS2_UNICODE_STRINGS);
 else
 {
  if (session_is_unicode() == 1)
    session_del_flags2 (flag:SMB_FLAGS2_UNICODE_STRINGS);
 }
 Session[6] = unicode;
}


function session_get_buffersize ()
{
 return Session[7];
}


function session_set_buffersize (size)
{
 Session[7] = size;
}


function session_get_sequencenumber ()
{
 return Session[8];
}


function session_increase_sequencenumber ()
{
 Session[8] = Session[8] + 1;
}


function session_get_mackey ()
{
 return Session[9];
}


function session_set_mackey (key)
{
 Session[9] = key;
}


function session_get_flags ()
{
 return Session[10];
}


function session_add_flags (flag)
{
 Session[10] = Session[10] | flag;
}


function session_get_flags2 ()
{
 return Session[11];
}


function session_add_flags2 (flag)
{
 Session[11] = Session[11] | flag;
}


function session_del_flags2 (flag)
{
 Session[11] = Session[11] ^ flag;
}

function session_get_hostname ()
{
 return Session[12];
}


function session_set_hostname (hostname)
{
 Session[12] = hostname;
}


function session_is_authenticated ()
{
 return Session[13];
}


function session_set_authenticated ()
{
 Session[13] = 1;
}


function session_is_guest ()
{
 return Session[14];
}


function session_set_guest (guest)
{
 Session[14] = guest;
}


function session_get_cid ()
{
 local_var cid;

 cid = Session[15];
 Session[15] = cid + 1;

 return cid;
}


function session_set_server_max_size (size)
{
 Session[16] = size;
}


function session_get_server_max_size ()
{
 return Session[16];
}


function session_set_host_info (domain, os, lan)
{
 local_var tmp;

 Session[17] = os;
 Session[18] = lan;
 Session[19] = domain;
}


#==================================================================#
# Section 3. Utilities                                             #
#==================================================================#

function hex2raw2(s)
{
 local_var i, j, ret, l;

 s = chomp(s);	# remove trailing blanks, CR, LF...
 l = strlen(s);
 ret = NULL;
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
						    

function inverse (data)
{
 local_var tmp, i, len;
 
 tmp = NULL;
 len = strlen(data);
 for (i=len-1; i >= 0; i--)
 {
  tmp += data[i];
 }

 return tmp;
}


function _hex (s)
{
 return inverse (data:hex2raw2(s:s));
}


function encode_uuid (uuid)
{
 local_var tmp, encoded, val;

 encoded = NULL;
 
 tmp = split (uuid, sep:"-", keep:FALSE);
 
 encoded = _hex(s:tmp[0]) +
           _hex(s:tmp[1]) +
	   _hex(s:tmp[2]) +
	   hex2raw2(s:tmp[3]) +
	   hex2raw2(s:tmp[4]);

 return encoded;
}


function decode_uuid (uuid)
{
 return hexstr(inverse(data:substr(uuid, 0, 3))) + "-" +
        hexstr(inverse(data:substr(uuid, 4, 5))) + "-" + 
        hexstr(inverse(data:substr(uuid, 6, 7))) + "-" +
        hexstr(substr(uuid, 8, 9)) + "-" +
        hexstr(substr(uuid, 10, 15));
}



function buffer_parameter (ref_id, size)
{
 return raw_dword (d:ref_id) + raw_dword (d:size);
}


function class_parameter (ref_id, name, size, _null)
{
 local_var tmp, len, uni, data;

 uni = session_is_unicode ();
 if (uni == 0)
   session_set_unicode (unicode:1);
 
 if (!isnull(_null) && (_null == FALSE))
   tmp = cstring (string:name, _null:1);
 else
   tmp = cstring (string:name);
 len = strlen (tmp);

 if ((len/2)%2 == 1)
   tmp += raw_word (w:0);

 if (!isnull (size))
   data = raw_word (w:len) + # length 
          raw_word (w:len);  # size
 else
   data = NULL;

 data += raw_dword (d:ref_id)     + # Referent ID
        raw_dword (d:len/2)      + # Max count
	raw_dword (d:0)          + # Offset
	raw_dword (d:len/2)      + # Actual Count
	tmp ;                      # name

 if (uni == 0)
   session_set_unicode (unicode:0); 
 return data;
}




function sid2string (sid)
{
 local_var ret, num, val, i;

 ret = NULL;
 if (strlen(sid) < 8)
   return NULL;

 val = get_byte (blob:sid, pos:0); 
 ret += string (val, "-");
 num = get_byte(blob:sid, pos:1);
 val = get_byte(blob:sid, pos:7);
 ret += string (val, "-");

 if (strlen(sid) < 8 + num*4)
   return NULL;

 for (i=0; i<num; i++)
 {
  val = get_dword (blob:sid, pos:8+i*4);
  ret += string (val,"-");
 }

 return substr (ret,0,strlen(ret)-2); 
}


function encode_int (i)
{
 local_var len, ret, j;

 len = strlen(i);
 ret = 0;

 for (j=0; j<len; j++)
   ret = ret * 10 + int(i[j]);
 
 return raw_dword (d:ret);
}


function encode_char (c)
{
 local_var ret;

 ret = encode_int (i:c);
 if (isnull(ret))
   return ret;

 return ret[0];
}

function string2sid (s)
{
 local_var ret, nums, len, i;

 nums = split (s, sep:"-", keep:FALSE);
 len = max_index (nums);
 if (len < 3)
   return NULL;

 ret = encode_char(c:nums[1]) + raw_string (len-3, 0,0,0,0,0) + encode_char(c:nums[2]);
 for (i=3; i<len; i++)
   ret += encode_int(i:nums[i]);

 return ret;
}


function parse_dacl (blob)
{
 local_var dacl, size, access_rights, sid, type, access, apply;

 if (strlen (blob) < 8)
   return NULL;

 dacl = NULL;

 access = get_byte (blob:blob, pos:0);
 apply = get_byte (blob:blob, pos:1);
 access_rights = get_dword (blob:blob, pos:4);
 size = get_word (blob:blob, pos:2); # size + 1 

 if (strlen(blob) != size)
   return NULL;

 sid = substr (blob, 8, size-1);

 dacl[0] = access_rights;
 dacl[1] = sid;
 dacl[2] = apply;
 dacl[3] = access; # deny or allow

 return dacl; 
}


function parse_pdacl (blob)
{
 local_var rev, size, nsid, i, pos, pdacl, length;

 if (strlen (blob) < 8)
   return NULL;

 rev = get_word (blob:blob, pos:0);
 size = get_word (blob:blob, pos:2);
 nsid = get_dword (blob:blob, pos:4);

 pos = 8;

 if (strlen (blob) < size)
   return NULL;

 pdacl = NULL;
 for (i=0; i<nsid; i++)
 {
  if (strlen(blob) < pos + 8)
    return NULL;

  length = get_word (blob:blob, pos:pos+2);
  if (strlen(blob) < pos+length)
    return NULL;

  pdacl[i] = substr (blob, pos, pos+length-1);  # length = real length + 1 ??
 
  pos += length;
 }

 return pdacl;
}


function parse_security_descriptor (blob)
{
 local_var rev, sbz1, sec_control, size, pos, security_descriptor;
 local_var psid_owner, psid_group, psid_sacl, psid_dacl;
 local_var sid_owner, sid_group, sacl, dacl, blo, pacl_sacl, pacl_dacl;

 sid_owner = sid_group = sacl = dacl = NULL;

 if (strlen (blob) < 20)
   return NULL;

 rev = get_byte (blob:blob, pos:0);
 sbz1 = get_byte (blob:blo, pos:1);
 sec_control = get_word (blob:blob, pos:2);

 psid_owner = get_dword (blob:blob, pos:4);
 psid_group = get_dword (blob:blob, pos:8);
 pacl_sacl = get_dword (blob:blob, pos:12);
 pacl_dacl = get_dword (blob:blob, pos:16);

 if (pacl_sacl != 0)
 {
  pos = pacl_sacl;
  if (strlen(blob) < pos + 4)
    return NULL;

  rev = get_word (blob:blob, pos:pos);
  size = get_word (blob:blob, pos:pos+2);

  if (strlen(blob) < pos + size)
    return NULL;

  sacl = substr (blob, pos, pos+size-1);
 }

 if (pacl_dacl != 0)
 {
  pos = pacl_dacl;
  if (strlen(blob) < pos + 4)
    return NULL;

  rev = get_word (blob:blob, pos:pos);
  size = get_word (blob:blob, pos:pos+2);

  if (strlen(blob) < pos + size)
    return NULL;

  dacl = substr (blob, pos, pos+size-1);
 }

 if (psid_owner != 0)
 {
  pos = psid_owner;
  sid_owner = get_sid (blob:blob, pos:pos);
  if (!sid_owner)
    return NULL;
 }
 
 if (psid_group != 0)
 {
  pos = psid_group;
  sid_group = get_sid (blob:blob, pos:pos);
  if (!sid_group)
    return NULL;
 }

 security_descriptor = NULL;
 security_descriptor[0] = sid_owner;
 security_descriptor[1] = sid_group;
 security_descriptor[2] = sacl;
 security_descriptor[3] = dacl;

 return security_descriptor;
}



function parse_lsalookupsid (data)
{
 local_var ret, len, pos;

 ret = NULL;
 ret [0] = get_dword (blob:data, pos:0);
 len = get_dword (blob:data, pos:4);
 ret [1] = substr (data, 8, 8+len-1);
 pos = len + 8;
 len = get_dword (blob:data, pos:pos);
 ret [2] = substr (data, pos+4, pos+4+len-1);

 return ret;
}


function get_sid (blob, pos)
{
 local_var count, len;

 if (strlen(blob) < pos + 8)
   return NULL;

 count = ord(blob[pos+1]);
 len = 8 + count*4;

 if (strlen(blob) < pos + len)
   return NULL;

 return substr (blob, pos, pos+len-1);
}



function class_name (name)
{
 local_var tmp, len, ret;

 if (isnull(name))
   return raw_dword (d:0);

 tmp = cstring (string:name);
 len  = strlen (tmp);

 if ((len%4) != 0)
   tmp += crap (data:raw_string(0), length:4-(len%4));

 if (session_is_unicode() == 1)
   len = len / 2;

 ret =  raw_dword (d:len)             + # length
        raw_dword (d:0)               + # offset
        raw_dword (d:len)             + # size
        tmp;                            # hostname

 return ret;
}



#==================================================================#
# Section 10. Old API wrapper                                      #
#==================================================================#


# This function MUST be redone                #
# we must check for local user (admin rights) #
#                   domain user (admin group) #

function registry_key_writeable_by_non_admin(security_descriptor)
{
 local_var pdacl, dacl, item, access_rights, sid;
 local_var ADMIN_SID, LOCAL_SYSTEM_SID, CREATOR_OWNER_SID;

 # Need to change this function
 return FALSE;

 pdacl = security_descriptor[3];
 pdacl = parse_pdacl (blob:pdacl);

 # sids - written the nessus way
 ADMIN_SID = "1-5-32-544";
 LOCAL_SYSTEM_SID = "1-5-18";
 CREATOR_OWNER_SID = "1-3-0";

 foreach item (pdacl)
 {
  dacl = parse_dacl (blob:item);
  access_rights = dacl[0];
  sid = sid2string (sid:dacl[1]);

  if ( (access_rights & WRITE_DAC)     ||
       (access_rights & WRITE_OWNER)   ||
       (access_rights & SYNCHRONIZE)   ||
       (access_rights & ACCESS_WRITE)  ||
       (access_rights & ACCESS_CREATE) ||
       (access_rights & GENERIC_WRITE) )
  {
   if((sid != ADMIN_SID) &&  
    (sid != LOCAL_SYSTEM_SID) && 
    (sid != CREATOR_OWNER_SID))
   {
    return(TRUE);
   }
  }
 }

 return FALSE;
}
