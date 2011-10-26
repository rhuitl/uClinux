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
# smb_sam.inc 
# $Revision: 1.1 $
#


#==================================================================#
# Section 6a. SAM API                                              #
#==================================================================#


#---------------------------------------------------------#
# Function    : SamConnect2                               #
# Description : Connects to the remote SAM pipe.          #
# Return      : ret[0] : registry handle                  #
#               ret[1] : registry pipe                    #
#               ret[2] : 1 (Pipe handle)                  #
#---------------------------------------------------------#

function SamConnect2 ()
{
 local_var fid, ret, data, resp, rep;

 fid = bind_pipe (pipe:"\samr", uuid:"12345778-1234-abcd-ef00-0123456789ac", vers:1);
 if (isnull (fid))
   return NULL;

 data = class_parameter (ref_id:0x00020000, name:"\"+session_get_hostname()) +
        raw_dword (d:0x30)        ; # Access mask

 data = dce_rpc_pipe_request (fid:fid, code:OPNUM_SAMCONNECT2, data:data);
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
# Function    : SamEnumerateDomainsInSamServer            #
# Description : Name is explicit enough                   #
# Return      : Array of Domain Names                     #
#---------------------------------------------------------#

function SamEnumerateDomainsInSamServer (handle)
{
 local_var data, resp, rep, ret, len, ref_id, count;
 local_var actual_count, max_count, offset, name, pos, i;

 data = handle[0]                     +  # Handle
	raw_dword (d:0)               +  # NULL handle
	raw_dword (d:0xFFFFFFFF) ;       # Max buf size
        
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMENUMDOM, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 24))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 handle = get_dword (blob:rep, pos:0);
 ref_id = get_dword (blob:rep, pos:4);
 count = get_dword (blob:rep, pos:8);
 ref_id = get_dword (blob:rep, pos:12);
 max_count = get_dword (blob:rep, pos:16);

 # we don't care about size and ref_id
 pos = count * 12 + 20;

 ret = NULL;

 for (i=0; i<count; i++)
 {
  if (strlen (rep) < pos + 12)
    return NULL;

  max_count = get_dword (blob:rep, pos:pos);
  offset = get_dword (blob:rep, pos:pos+4);
  actual_count = get_dword (blob:rep, pos:pos+8);

  if (session_is_unicode() == 1)
    actual_count = actual_count * 2;

  if (strlen(rep) < pos + 12 + actual_count)
    return NULL;

  name = get_string2 (blob:rep, pos:pos + 12, len:actual_count);
  
  pos += actual_count + 12;

  while ((actual_count % 4) != 0)
  {
   actual_count ++;
   pos ++;
  }

  ret[i] = name;
 }
 
 return ret;
}


#---------------------------------------------------------#
# Function    : SamLookupDomainInSamServer                #
# Description : Name is explicit enough                   #
# Return      : Domain SID                                #
#---------------------------------------------------------#

function SamLookupDomainInSamServer (handle, domain)
{
 local_var data, resp, rep;

 data = handle[0]                     +  # Handle
	class_parameter (ref_id:0x00020000, name:domain, size:TRUE, _null:FALSE);
        
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMLOOKUP, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 36))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;
 
 return substr(rep, 8, strlen(rep)-5);
}


#---------------------------------------------------------#
# Function    : SamOpenDomain                             #
# Description : Open the given domain sid                 #
# Return      : ret[0] domain handle                      #
#               ret[1] FID                                #
#               ret[2] reserved                           #
#---------------------------------------------------------#

function SamOpenDomain (handle, sid, access)
{
 local_var data, resp, rep, ret, len;

 data = handle[0]                     +  # Handle
        raw_dword (d:access)          +  # Access mask
        raw_dword (d:ord(sid[1]))     +  # count
        sid ;                            # sid

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMOPENDOM, data:data);
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
# Function    : SamLookupNamesInDomain                    #
# Description : search user in domain                     #
# Return      : user rid                                  #
#                                                         #
# Note        : Support only one name (not array)         #
#---------------------------------------------------------#

function SamLookupNamesInDomain (handle, user)
{
 local_var data, resp, rep, ret, len;

 data = handle[0]                     +  # Handle
        raw_dword (d:1)               +  # count
        raw_dword (d:1000)            +  # max count
        raw_dword (d:0)               +  # offset
        raw_dword (d:1)               +  # actual count
	class_parameter (ref_id:0x00020000, name:user, size:TRUE, _null:FALSE);        

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMLOOKUPNAME, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 36))
   return NULL;
 
 resp = get_dword (blob:rep, pos:32);
 if (resp != STATUS_SUCCESS)
   return NULL;

 return get_dword (blob:rep, pos:12);
}


#---------------------------------------------------------#
# Function    : SamOpen                                   #
# Description : Open the given rid                        #
# Return      : ret[0] handle                             #
#               ret[1] FID                                #
#               ret[2] reserved                           #
#---------------------------------------------------------#

function SamOpen (handle, rid, access, code)
{
 local_var data, resp, rep, ret, len;

 data = handle[0]                     +  # Handle
        raw_dword (d:access)          +  # Access mask
        raw_dword (d:rid)             ;  # count

 data = dce_rpc_pipe_request (fid:handle[1], code:code, data:data);
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
# Function    : SamOpenUser                               #
# Description : Open the given user rid                   #
# Return      : ret[0] user handle                        #
#               ret[1] FID                                #
#               ret[2] reserved                           #
#---------------------------------------------------------#

function SamOpenUser (handle, rid, access)
{
 return SamOpen (handle:handle, rid:rid, access:access, code:OPNUM_SAMOPENUSER);
}


#---------------------------------------------------------#
# Function    : SamOpenGroup                              #
# Description : Open the given group rid                  #
# Return      : ret[0] group handle                       #
#               ret[1] FID                                #
#               ret[2] reserved                           #
#---------------------------------------------------------#

function SamOpenGroup (handle, rid, access)
{
 return SamOpen (handle:handle, rid:rid, access:access, code:OPNUM_SAMOPENGROUP);
}


#---------------------------------------------------------#
# Function    : SamOpenAlias                              #
# Description : Open the given alias                      #
# Return      : ret[0] alias handle                       #
#               ret[1] FID                                #
#               ret[2] reserved                           #
#---------------------------------------------------------#

function SamOpenAlias (handle, rid, access)
{
 local_var data, resp, rep, ret, len;

 data = handle[0]                     +  # Handle
        raw_dword (d:access)          +  # Access mask
        raw_dword (d:rid)             ;  # count

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMOPENALIAS, data:data);
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
# Function    : SamGetGroupsForUser                       #
# Description : return user groups                        #
# Return      : array of rid                              #
#---------------------------------------------------------#

function SamGetGroupsForUser (handle)
{
 local_var data, resp, rep, ret, len, i, pos, ref_id, count, max_count;

 data = handle[0] ;

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMGETGROUPS, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 20))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep-4));
 if (resp != STATUS_SUCCESS)
   return NULL;

 ref_id = get_dword (blob:rep, pos:0);
 count  = get_dword (blob:rep, pos:4);
 ref_id = get_dword (blob:rep, pos:8);
 max_count = get_dword (blob:rep, pos:12);

 pos = 16;

 if (strlen(rep) < pos + count * 8 + 4)
   return NULL;

 ret = NULL;
 for (i=0; i<count; i++)
 {
  ret[i] = get_dword (blob:rep, pos:pos);
  pos += 8;
 }
 
 return ret;
}


#---------------------------------------------------------#
# Function    : SamGetMembersInAlias                      #
# Description : return members                            #
# Return      : array of rid                              #
#---------------------------------------------------------#

function SamGetMembersInAlias (handle)
{
 local_var data, resp, rep, ret, len, i, pos, ref_id, count, max_count, num;

 data = handle[0] ;

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMGETMEMALIAS, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 20))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep-4));
 if (resp != STATUS_SUCCESS)
   return NULL;

 count  = get_dword (blob:rep, pos:0);
 ref_id = get_dword (blob:rep, pos:4);
 max_count = get_dword (blob:rep, pos:8);

 # we don't care about ref_id
 pos = 12 + count * 4;

 if (strlen(rep) < pos + 4)
   return NULL;

 ret = NULL;
 for (i=0; i<count; i++)
 {
  if (strlen(rep) < pos+12)
    return NULL;

  num = get_dword (blob:rep, pos:pos);
  if (strlen(rep) < pos+12+num*4)
    return NULL;

  ret[i] = substr(rep, pos+4, pos+12+num*4-1);
  pos += 12 + num*4;
 }
 
 return ret;
}


#---------------------------------------------------------#
# Function    : SamGetMembersInGroup                      #
# Description : return members                            #
# Return      : array of rid                              #
#---------------------------------------------------------#

function SamGetMembersInGroup (handle)
{
 local_var data, resp, rep, ret, len, i, pos, ref_id, count, max_count, num;

 data = handle[0] ;

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMGETMEMGROUP, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 20))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep-4));
 if (resp != STATUS_SUCCESS)
   return NULL;

 count  = get_dword (blob:rep, pos:4);
 pos = 20;

 if (strlen(rep) < pos + count*4 + 4)
   return NULL;

 ret = NULL;
 for (i=0; i<count; i++)
 {
  ret[i] = get_dword (blob:rep, pos:pos);
  pos += 4;
 }
 
 return ret;
}


#---------------------------------------------------------#
# Function    : SamLookupIdsInDomain                      #
# Description : return ids names                          #
# Return      : array of names                            #
#---------------------------------------------------------#

function SamLookupIdsInDomain (handle, ids)
{
 local_var data, resp, rep, ret, len, i, pos, ref_id, count, max_count, actual_count, offset, id, name;

 data = handle[0]                    +
        raw_dword (d:max_index(ids)) + # count
        raw_dword (d:1000)           + # max_count
        raw_dword (d:0)              + # offset
        raw_dword (d:max_index(ids)) ; # actual count

 foreach id (ids)
   data += raw_dword (d:id);

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMLOOKUPIDS, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 20))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep-4));
 if (resp != STATUS_SUCCESS)
   return NULL;

 count = get_dword (blob:rep, pos:0);
 ref_id = get_dword (blob:rep, pos:4);
 max_count = get_dword (blob:rep, pos:8);

 # we don't care about size and ref_id
 pos = count * 8 + 12;

 ret = NULL;

 for (i=0; i<count; i++)
 {
  if (strlen (rep) < pos + 12)
    return NULL;

  max_count = get_dword (blob:rep, pos:pos);
  offset = get_dword (blob:rep, pos:pos+4);
  actual_count = get_dword (blob:rep, pos:pos+8);

  if (session_is_unicode() == 1)
    actual_count = actual_count * 2;

  if (strlen(rep) < pos + 12 + actual_count)
    return NULL;

  name = get_string2 (blob:rep, pos:pos + 12, len:actual_count);
  
  pos += actual_count + 12;

  while ((actual_count % 4) != 0)
  {
   actual_count ++;
   pos ++;
  }

  ret[i] = name;
 }
 
 return ret;
}


#---------------------------------------------------------#
# Function    : SamQueryInformationUser                   #
# Description : return user information                   #
# Return      : array of information  (level 21)          #
# Note        : Incomplete !!!                            #
#---------------------------------------------------------#

function SamQueryInformationUser (handle)
{
 local_var data, resp, rep, ret, pos, ref_id, level;

 data = handle[0]       +
        raw_word (w:21) ; # level

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMQUERYINFOU, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 52))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep-4));
 if (resp != STATUS_SUCCESS)
   return NULL;

 ref_id = get_dword (blob:rep, pos:0);
 level = get_dword (blob:rep, pos:4);
 
 pos = 8;

 ret = NULL;
 ret[0] = substr(rep, pos, pos+7);     # last logon time
 ret[1] = substr(rep, pos+8, pos+15);  # last logoff time
 ret[2] = substr(rep, pos+16, pos+23); # pwd last set
 ret[3] = substr(rep, pos+24, pos+31); # acct expiry
 ret[4] = substr(rep, pos+32, pos+39); # pwd can change
 ret[5] = substr(rep, pos+40, pos+47); # pwd must change

 # we don't care about name info (maybe later)
 pos = pos + 20*8   # time + string
           + 8 ;    # RID + GRID
 
 if (strlen(rep) < pos + 4)
   return NULL;

 ret[6] = get_dword (blob:rep, pos:pos);

 return ret;
}



#---------------------------------------------------------#
# Function    : SamQueryInformationDomain                 #
# Description : return domain information                 #
# Return      : array of information  (level 1,3 or 12)   #
# Note        : Incomplete !!!                            #
#---------------------------------------------------------#

function SamQueryInformationDomain (handle, level)
{
 local_var data, resp, rep, ret, pos, ref_id, lev;

 data = handle[0]       +
        raw_word (w:level) ; # level

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMQUERYINFOD, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 8))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep-4));
 if (resp != STATUS_SUCCESS)
   return NULL;

 ref_id = get_dword (blob:rep, pos:0);
 lev = get_word (blob:rep, pos:4);
 
 pos = 8;

 ret = NULL;

 if (lev == 1)
 {
  if (strlen(rep) != 36)
    return NULL;

  ret[0] = get_word (blob:rep, pos:pos);    # min pass len
  ret[1] = get_word (blob:rep, pos:pos+2);  # pass history len
  ret[2] = get_dword (blob:rep, pos:pos+4); # password must meet complexity requirements
  ret[3] = convert_time_to_sec(time:substr (rep, pos+8, pos+15));    # max pass age
  ret[4] = convert_time_to_sec(time:substr (rep, pos+16, pos+23));   # min pass age
 }
 else if (lev == 3)
 {
  if (strlen(rep) != 20)
    return NULL;
  
  ret[0] = convert_time_to_sec(time:substr(rep, pos, pos+7));     # force logoff
 }
 else if (lev == 12)
 {
  if (strlen(rep) != 32)
    return NULL;
  
  ret[0] = convert_time_to_sec(time:substr (rep, pos, pos+7));        # lockout duration
  ret[1] = convert_time_to_sec(time:substr (rep, pos+8, pos+15));     # lockout duration
  ret[2] = get_word (blob:rep, pos:pos+16); # lockout threshold
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : SamGetAliasMemberShip                     #
# Description : return aliases                            #
#---------------------------------------------------------#

function SamGetAliasMemberShip (handle, sid, rids, urid)
{
 local_var data, resp, rep, ret, i, tmp_sid, count, num_sid, ref_id, rid, pos, num_id;

 tmp_sid = sid[0] + raw_byte(b:ord(sid[1]) + 1) + substr (sid, 2, strlen(sid)-1);
 count = ord(sid[1]) + 1;

 num_id = max_index(rids) + 1;

 data = handle[0]       +
        raw_dword (d:num_id)      + # count
        raw_dword (d:0x00146668)  + # ref_id
        raw_dword (d:num_id)      ; # max count

 ref_id = 0x001466a8;

 for (i=0; i<num_id; i++)
 {
  data += raw_dword (d:ref_id);
  ref_id += 0x28;
 }

 # we add user rid first
 data += raw_dword (d:count) + tmp_sid + raw_dword (d:urid);

 # and group rids
 foreach rid (rids)
   data += raw_dword (d:count) + tmp_sid + raw_dword (d:rid);

 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMGETALIASM, data:data);
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 12))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 count = get_dword (blob:rep, pos:0);
 if (count == 0)
   return NULL;

 ret = NULL;
 pos = 12;

 if (strlen(rep) < pos + count*4 + 4)
   return NULL;

 for (i=0; i<count; i++)
 {
  ret[i] = get_dword(blob:rep, pos:pos);
  pos += 4;
 }

 return ret;  
}


#---------------------------------------------------------#
# Function    : SamCloseHandle                            #
# Description : Close Handle                              #
#---------------------------------------------------------#

function SamCloseHandle (handle)
{
 local_var data, rep, code, ret;

 code = NULL;
 
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_SAMCLOSEHANDLE, data:handle[0]);
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

