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
# smb_reg.inc
# $Revision: 1.1 $
#


#==================================================================#
# Section 7. Registry API                                          #
#==================================================================#



#---------------------------------------------------------#
# Function    : RegConnectRegistry                        #
# Description : Connects to the remote registry.          #
#               if not hkey connects to HKLM              #
# Return      : ret[0] : registry handle                  #
#               ret[1] : registry pipe                    #
#               ret[2] : 1 (Pipe handle)                  #
#---------------------------------------------------------#

function RegConnectRegistry (hkey)
{
 local_var fid, ret, data, type, resp, rep;

 if (isnull (hkey))
   type = HKEY_LOCAL_MACHINE;
 else
   type = hkey;

 fid = bind_pipe (pipe:"\winreg", uuid:"338cd001-2244-31f1-aaaa-900038001003", vers:1);
 if (isnull (fid))
   return NULL;

 data = raw_dword (d:0x00020000) +
        raw_word (w:0x75A0) +
	raw_word (w:0x0000) +
	raw_dword (d:0x02000000) ; # FULL_ACCESS

 data = dce_rpc_pipe_request (fid:fid, code:type, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;
 
 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = fid;
 ret[2] = 1;

 return ret;
}



#---------------------------------------------------------#
# Function    : RegOpenKey                                #
# Description : Open the given key                        #
# Return      : ret[0] Key handle                         #
#               ret[1] FID                                #
#               ret[2] reserved                           #
#---------------------------------------------------------#

function RegOpenKey (handle, key, mode)
{
 local_var data, resp, rep, name, ret, len;

 name = cstring (string:key);
 len = strlen(name);

 data = handle[0]                     +  # Handle

	class_parameter (ref_id:0x00020000, name:key, size:TRUE) +

	raw_dword (d:0)         +  # Unknown
	raw_dword (d:mode) ;       # Mask
        
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_OPENKEY, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;
 
 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = handle[1];
 ret[2] = 0;
 
 return ret;
}



#---------------------------------------------------------#
# Function    : RegQueryInfoKey                           #
# Description : Retrieve key information                  #
# Return      : returns number of values and sub keys     #
#               ret[0] values                             #
#               ret[1] subkeys                            # 
#---------------------------------------------------------#

function RegQueryInfoKey (handle)
{
 local_var data, resp, rep, ret;

 data = handle[0]          +  # Handle
        raw_word (w:0)     +  # Length
	raw_word (w:0)     +  # Size
	raw_dword (d:0);      # NULL 
 
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_QUERYINFOKEY, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Class (bad parsed here)
 # num subkeys
 # max subkey len
 # reserved
 # num value
 # max value len
 # max valbuf size
 # secdesc len
 # mod time
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 48))
   return NULL;
 
 resp = get_dword (blob:rep, pos:44);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = get_dword (blob:rep, pos:20);
 ret[1] = get_dword (blob:rep, pos:8);

 return ret;
}



#---------------------------------------------------------#
# Function    : RegQueryValue                             #
# Description : Retrieve value about key's item           #
# Return      : returns item value                        #
#               ret[0] type                               #
#               ret[1] value                              #
#---------------------------------------------------------#

function RegQueryValue (handle, item)
{
 local_var data, resp, rep, ret, name, len;
 local_var ref_id, key_type, key_data, code, max_count, offset, actual_count, pos;

 if (strlen(item) > 0)
   name = class_parameter (ref_id:0x00020000, name:item, size:TRUE);
 else
   name = raw_word(w:2) + raw_word (w:0) + raw_dword (d:0);  # (default) value does not work with RegQueryValueEx

 data = handle[0]  +  # Handle

        # Class
        name  +

	# Reserved
        buffer_parameter (ref_id:0x00020004, size:0) +

        # Offered
        buffer_parameter (ref_id:0x00020008, size:0xFFFF) +

        raw_dword (d:0)           +  # unknown
	raw_dword (d:0)           +  # unknown

        # Offered
        buffer_parameter (ref_id:0x0002000C, size:0xFFFF) +
        
	# Returned
        buffer_parameter (ref_id:0x00020010, size:0);


 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_QUERYVALUE, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 24))
   return NULL;
 
 # Key Type
 ref_id = get_dword (blob:rep, pos:0);
 key_type = get_dword (blob:rep, pos:4);

 # Key Data
 ref_id = get_dword (blob:rep, pos:8);
 max_count = get_dword (blob:rep, pos:12);
 offset = get_dword (blob:rep, pos:16);
 actual_count = get_dword (blob:rep, pos:20);
 if (strlen(rep) < 24+actual_count+20)
   return NULL;

 pos = 0;

 if ((key_type == REG_SZ) || (key_type == REG_EXPAND_SZ) || (key_type == REG_MULTI_SZ))
 {
   key_data = get_string2 (blob:rep, pos:24, len:actual_count, _type:UNICODE_STRING);
   while ((actual_count % 4) != 0)
   {
    actual_count++;
    pos++;
   }
 }
 else if (key_type == REG_DWORD)
 {
  key_data = get_dword (blob:rep, pos:24);
 }
 else
  key_data = substr (rep, 24, 24+actual_count-1);

 # Return code
 code = get_dword (blob:rep, pos:strlen(rep)-4);
 if (code != STATUS_SUCCESS)
   return NULL;
 
 ret = NULL;
 ret[0] = key_type;
 ret[1] = key_data;  # we must convert type here
 
 return ret;
}



#---------------------------------------------------------#
# Function    : RegEnumValue                              #
# Description : Retrieve index type and value             #
# Return      : returns key value                         #
#               ret[0] type                               #
#               ret[1] value                              #
#---------------------------------------------------------#

function RegEnumValue (handle, index)
{
 local_var data, resp, rep, ret, name, len, pos;
 local_var unknown1, unknown2, ref_id, key_type, key_name, reserved, val, code, len_2;

 data = handle[0]  +  # Handle

	raw_dword (d:index)          +  # num
	raw_dword (d:0x20000000)     +  # unknown

	raw_dword (d:0x20000)        +  # Referent ID
	raw_dword (d:0x1000)         +  # unknown
	raw_dword (d:0)              +  # unknown
	raw_dword (d:0)              +  # unknown

	raw_dword (d:0x20004)        +  # Referent ID
	raw_dword (d:0)              +  # Pointer
	raw_dword (d:0)              +  # reserved

        buffer_parameter (ref_id:0x00020008, size:0) +

        buffer_parameter (ref_id:0x0002000C, size:0);

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_ENUMVALUE, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 24))
   return NULL;
 
 # Key name
 len = get_word (blob:rep, pos:0);
 unknown1 = get_word (blob:rep, pos:2); # 0x200 ?
 ref_id = get_dword (blob:rep, pos:4);
 unknown2 = get_dword (blob:rep, pos:8);
 reserved = get_dword (blob:rep, pos:12);
 len_2 = get_dword (blob:rep, pos:16);
 
 pos = 20 + len;
 # Extra 2 bytes pad if len_2 odd
 if ((len_2 % 2) == 1)
   pos += 2; 

 if (strlen (rep) < pos+32)
   return NULL;

 key_name = get_string (blob:rep, pos:20);
 
 # Key type
 ref_id = get_dword (blob:rep, pos:pos);
 key_type = get_dword (blob:rep, pos:pos+4);
 reserved = get_dword (blob:rep, pos:pos+8);

 # Offered
 ref_id = get_dword (blob:rep, pos:pos+12);
 val = get_dword (blob:rep, pos:pos+16);

 # Returned
 ref_id = get_dword (blob:rep, pos:pos+20);
 val = get_dword (blob:rep, pos:pos+24);

 # Return code
 code = get_dword (blob:rep, pos:pos+28);
 if (code != STATUS_SUCCESS)
   return NULL;
 
 ret = NULL;
 ret[0] = key_type;
 ret[1] = key_name;

 return ret;
}


#---------------------------------------------------------#
# Function    : RegEnumKey                                #
# Description : Returns key's index name                  #
#---------------------------------------------------------#

function RegEnumKey (handle, index)
{
 local_var data, resp, rep, ret, name, len, len_2;
 local_var unknown1, unknown2, ref_id, key_type, key_name, reserved, code, pos;

 data = handle[0]  +  # Handle

	raw_dword (d:index)          +  # num
	raw_dword (d:0x20000000)     +  # unknown

	raw_dword (d:0x20000)        +  # Referent ID
	raw_dword (d:0x1000)         +  # unknown
	raw_dword (d:0)              +  # unknown
	raw_dword (d:0)              +  # unknown

	raw_dword (d:0x20004)        +  # Referent ID
	raw_dword (d:0)              +  # Pointer
	raw_dword (d:0)              +  # reserved
	raw_dword (d:0) ;               # reserved

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_ENUMKEY, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 24))
   return NULL;
 
 # Key name
 len = get_word (blob:rep, pos:0);
 unknown1 = get_word (blob:rep, pos:2); # 0x200 ?
 ref_id = get_dword (blob:rep, pos:4);
 unknown2 = get_dword (blob:rep, pos:8);
 reserved = get_dword (blob:rep, pos:12);
 len_2 = get_dword (blob:rep, pos:16);
 
 pos = 20 + len;
 # Extra 2 bytes pad if len_2 odd
 if ((len_2 % 2) == 1)
   pos += 2; 

 if (strlen (rep) < pos+20)
   return NULL;

 key_name = get_string (blob:rep, pos:20);
 
 #Returned 
 ref_id = get_dword (blob:rep, pos:pos);
 reserved = get_dword (blob:rep, pos:pos+4);
 reserved = get_dword (blob:rep, pos:pos+8);
 reserved = get_dword (blob:rep, pos:pos+12);

 # Return code
 code = get_dword (blob:rep, pos:pos+16);
 if (code != STATUS_SUCCESS)
   return NULL;
 
 ret = key_name;

 return ret;
}



#---------------------------------------------------------#
# Function    : RegCloseKey                               #
# Description : Close key handle                          #
# Return      : 1 on success                              #
#---------------------------------------------------------#

function RegCloseKey (handle)
{
 local_var data, rep, code, ret;

 code = NULL;
 
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_CLOSEKEY, data:handle[0]);
 if (data)
 {
  rep = dce_rpc_parse_response (fid:handle[1], data:data);
  if (rep && (strlen (rep) == 24))
  { 
   # NULL handle (useless) + code
   # Return code
   code = get_dword (blob:rep, pos:20);
  }
 }

 if (handle[2] == 1)
   ret = smb_close (fid:handle[1]);
 
 if (isnull (code) || (code != STATUS_SUCCESS) || (ret != 1))
   return NULL;
 
 return 1;
}



#---------------------------------------------------------#
# Function    : RegGetKeySecurity                         #
# Description : Return Key Security Descriptor            #
# Type        : xxx_SECURITY_INFORMATION                  #
#               xxx = DACL, SACL, GROUP, OWNER            #
#               | to use multiple level                   #
#---------------------------------------------------------#

function RegGetKeySecurity (handle, type)
{
 local_var data, rep, ret, len, code, ref_id, offset, size, unknown, sec_desc, size2;
 local_var length, max_count, actual_count;

 data = handle[0] +
        raw_dword (d:type) +
	raw_dword (d:0)    + # Referent ID;
	raw_dword (d:0)    + # Length
	raw_dword (d:0)    + # Offset
	raw_dword (d:0xFFFFFFFF) ;    # Size
	
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_GETKEYSECURITY, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 16))
   return NULL;
 
 # Referent ID
 # length
 # offset
 # return code

 ref_id = get_dword (blob:rep, pos:0);
 len = get_dword (blob:rep, pos:4);
 offset = get_dword (blob:rep, pos:8);
 code = get_dword (blob:rep, pos:strlen(rep)-4);
 if (code != ERROR_INSUFFICIENT_BUFFER)
   return NULL;
 
 # Now we do the same request but with the length of our allowed buffer (useless in fact with nasl)

 data = handle[0]                +
        raw_dword (d:type)       +
	raw_dword (d:0x20000)    + # Referent ID;
	raw_dword (d:len)        + # Length
	raw_dword (d:0)          + # Offset
	raw_dword (d:len)        + # Size
	raw_dword (d:0)          + # reserved
	raw_dword (d:0) ;          # reserved
	
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_GETKEYSECURITY, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 24))
   return NULL;
 
 # Referent ID
 # length
 # offset
 # return code

 ref_id = get_dword (blob:rep, pos:0);
 len = get_dword (blob:rep, pos:4);
 size = get_dword (blob:rep, pos:8);
 actual_count = get_dword (blob:rep, pos:12);
 offset = get_dword (blob:rep, pos:16);
 max_count = get_dword (blob:rep, pos:20);

 if (strlen (rep) < 24+len+4)
   return NULL;

 sec_desc = substr (rep, 24, 24+len-1);
 sec_desc = parse_security_descriptor (blob:sec_desc);

 code = get_dword (blob:rep, pos:24+len);
 if (code != STATUS_SUCCESS)
   return NULL;
 
 return sec_desc;
}

