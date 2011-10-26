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
# smb_dcerpc.inc
# $Revision: 1.2 $
#



function dce_rpc (type,cid,data,flags)
{
 local_var packet, flag;

 if (isnull(flags))
   flag = 3; # FIRST fragment, LAST fragment
 else
   flag = flags;

 packet = raw_byte (b:5) +                # version
          raw_byte (b:0) +                # version (minor)
	  raw_byte (b:type) +             # packet type
	  raw_byte (b:flag) +             # packet flags
	  raw_dword (d:16) +              # data representation (little-endian/ascii)
	  raw_word (w:16+strlen(data)) +  # Frag length
	  raw_word (w:0) +                # auth length
	  raw_dword (d:cid) +             # caller ID
	  data;
 
 return packet;
}


function dce_rpc_bind (cid, uuid, vers)
{
 local_var packet;
 
 packet = raw_word (w:4280) +       # Max Xmit Frag
          raw_word (w:4280) +       # Max recv Frag
	  raw_dword (d:0)   +       # Assoc group
	  raw_dword (d:1)   +       # Num context items
	  raw_word (w:0)    +       # Context ID
	  raw_word (w:1)    +       # num trans item
	  encode_uuid (uuid:uuid) + # Interface uuid
	  raw_word (w:vers)    +       # interface version
	  raw_word (w:0)    +       # interface version (minor)
	  encode_uuid (uuid:"8a885d04-1ceb-11c9-9fe8-08002b104860") +
	  raw_dword (d:2) ;         # syntax version

 return dce_rpc (type:DCE_RPC_BIND, cid:cid, data:packet);	  
}


function dce_rpc_parse_bind_ack (data)
{
 local_var len, res;

 if (strlen (data) < 26)
   return NULL;
 len = get_word (blob:data, pos:24);
 if ((len%2) != 0)
   len += 1; # byte padding

 if (strlen (data) < 26+len+4)
   return NULL;

 res = get_word (blob:data, pos:26+len+4);
 return res;
}


function dce_rpc_request (code, data, flags, id)
{
 local_var packet, cid;

 if (isnull(id))
   cid = session_get_cid();
 else
   cid = id;

 packet = raw_dword (d:strlen(data))  +       # Alloc hint
          raw_word (w:0)              +       # Context ID
	  raw_word (w:code)           +       # Opnum
          data;
 
 if (isnull(flags))
   return dce_rpc (type:DCE_RPC_REQUEST, cid:cid, data:packet);
 else
   return dce_rpc (type:DCE_RPC_REQUEST, cid:cid, data:packet, flags:flags);
}


function dce_rpc_pipe_request (fid, code, data)
{
 local_var tmp, rep, len, flag, ret, offset, cid, dat, size, data_len;

 size = session_get_server_max_size() - 110;
 cid = session_get_cid();
 offset = 0;
 data_len = strlen(data);

 if (data_len > size)
 {
   flag = 1; # FIRST fragment
   tmp = substr (data, 0, size-1);
   len = size;
 }
 else
 {
   flag = 3; # FIRST fragment, LAST fragment
   tmp = data;
   len = data_len;
 }

 while (len < data_len)
 {
  ret = smb_write_and_x (fid:fid, offset:offset, mode:WRITE_START, data:dce_rpc_request (code:code, data:tmp, flags:flag, id:cid));
  if (isnull (ret) || (ret != 1))
    return NULL;

  offset += strlen(tmp);

  if ((len + size) < data_len)
  {
   flag = 0;
   tmp = substr (data, len, len+size-1);
   len += size;
  }
  else
  {
   flag = 2;
   tmp = substr (data, len, data_len-1);
   break;
  }
 }

 ret = smb_trans_pipe (fid:fid, data:dce_rpc_request (code:code, data:tmp, flags:flag, id:cid));
 if (isnull (ret))
   return NULL;

 return ret;
}


function dce_rpc_parse_response (fid, data)
{
 local_var resp, flag, len, alloc, tmp, dat;

 if (strlen (data) < 24)
   return NULL;
   
 flag = get_byte (blob:data, pos:3);
 len = get_word (blob:data, pos:8) - 24;
 alloc = get_dword (blob:data, pos:16);

 if (strlen (data) < (24 + len))
   return NULL;
   
 resp = substr (data, 24, 24 + len - 1);

 # If it is not the last dce_rpc packet we continue to read
 while (!(flag & 2))
 {
  # we read only 1000 bytes at a time
  tmp = smb_read_and_x (fid:fid, offset:0, length:1024);
  if (strlen (tmp) < 24)
    return NULL;

  flag = get_byte (blob:tmp, pos:3);
  len = get_word (blob:tmp, pos:8);
  alloc = get_dword (blob:tmp, pos:16);

  while (strlen (tmp) < len)
  {
   dat = smb_read_and_x (fid:fid, offset:0, length:1024);
   if (!dat)
     return NULL;
   tmp += dat;
  }
  
  resp += substr (tmp, 24, 24 + len - 1);
 }

 return resp;
}



function bind_pipe (pipe, uuid, vers)
{
 local_var fid, ret, data;
 
 ret = smb_create_and_x (name:pipe,
                         desired_access:FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA |
                                        FILE_READ_EA | FILE_WRITE_EA | 
                                        FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                         flags_attributes:0,
                         share_mode:FILE_SHARE_READ | FILE_SHARE_WRITE,
                         create_disposition:OPEN_EXISTING,
                         create_options:0x40);
 if (isnull(ret))
   return NULL;
 
 fid = ret[0];

 ret = smb_write_and_x (fid:fid, offset:0, mode:WRITE_START, data:dce_rpc_bind(cid:session_get_cid(), uuid:uuid, vers:vers));
 if (isnull (ret) || (ret != 1))
   return NULL;

 data = smb_read_and_x (fid:fid, offset:0, length:1024);
 if (!data)
   return NULL;
 
 ret = dce_rpc_parse_bind_ack (data:data);
 if (isnull (ret) || (ret != 0))
   return NULL;

 return fid;
}


