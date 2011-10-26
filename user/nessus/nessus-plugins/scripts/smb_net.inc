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
# smb_net.inc 
# $Revision: 1.2 $
#

#==================================================================#
# Section 6b. Network Management API                               #
#==================================================================#



function NetGetInfo (pipe, uuid, vers, level, opnum)
{
 local_var fid, data, rep, resp, info_level, info_struct, ret;

 fid = bind_pipe (pipe:pipe, uuid:uuid, vers:vers);

 data = class_parameter (ref_id:0x00020000, name:"\\" + session_get_hostname ()) +

	raw_dword (d:level) ;      # Info level

 data = dce_rpc_pipe_request (fid:fid, code:opnum, data:data);
 if (!data)
 {
   smb_close (fid:fid);
   return NULL;
 }

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) < 8))
 {
  smb_close (fid:fid);
  return NULL;
 }
 
 info_level = get_dword (blob:rep, pos:0);
 info_struct = substr (rep, 4, strlen(rep) - 5);

 resp = get_dword (blob:rep, pos:strlen(rep) - 4);
 if (resp != STATUS_SUCCESS)
 {
  smb_close (fid:fid);
  return NULL;
 }

 ret = NULL;
 ret[0] = info_level;
 ret[1] = info_struct;

 smb_close (fid:fid);
 
 return ret;
}



function NetEnum (pipe, level, uuid, vers, opnum)
{
 local_var fid, name, len, data, rep, resp, ret;

 fid = bind_pipe (pipe:pipe, uuid:uuid, vers:vers);

 data = class_parameter (ref_id:0x00020000, name:"\"+session_get_hostname()) +

	raw_dword (d:level)      + # Info level
        
        # share info container
        raw_dword (d:level)      + # Share Info level (multi share request with different level ?)
        raw_dword (d:0x00020004) + # Referent ID
        raw_dword (d:0)          + # number of entries
        raw_dword (d:0)          + # share info array (NULL)

        raw_dword (d:0xFFFFFFFF) + # preferred length
        
        # Enum handle
        buffer_parameter (ref_id:0x00020008, size:0);

 data = dce_rpc_pipe_request (fid:fid, code:opnum, data:data);
 if (!data)
 {
   smb_close (fid:fid);
   return NULL;
 }

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) < 24))
 {
  smb_close (fid:fid);
  return NULL;
 }

 resp = get_dword (blob:rep, pos:strlen(rep) - 4);
 if (resp != STATUS_SUCCESS)
 {
  smb_close (fid:fid);
  return NULL;
 }

 ret = substr (rep, 0, strlen(rep)-4-1);

 smb_close (fid:fid);
 
 return ret;
}




#---------------------------------------------------------#
# Function    : NetUseAdd                                 #
# Description : Connects to the remote share.             #
#               If no share is specified authenticates    #
#               for futur use (anonymous if no login)     #
# Return      : Return 1 on success                       #
#                     -1 if login failed                  #
#                      0 if share connection failed       #
#---------------------------------------------------------#

function NetUseAdd (login,password,domain,share)
{
 local_var ret;

 if (!session_is_authenticated ())
 {
  if (netbios_session_request () != TRUE)
   return -1;

  if (smb_login (login:login, password:password, domain:domain) != 1)
    return -1;
  else
    session_set_authenticated();
 }
 
 if (!isnull (share))
 {
  ret = smb_tree_connect_and_x (share:share);
  if (!ret)
    return 0;
 }

 return 1;
}



#---------------------------------------------------------#
# Function    : NetUseDel                                 #
# Description : Delete connection to the remote share.    #
# Optional    : close. If close == TRUE or not specified  #
#                      logoff and close socket            # 
#---------------------------------------------------------#

function NetUseDel (close)
{
 if (smb_tree_disconnect () != 1)
   return -1;

 if (isnull(close) || (close == TRUE))
 {
   if (session_is_authenticated ())
   {
    smb_logoff_andx ();
   }
   close (session_get_socket());
 }

 return 1;
}


#---------------------------------------------------------#
# Function    : NetServerGetInfo                          #
# Description : Return host information                   #
#---------------------------------------------------------#

function NetServerGetInfo (level)
{
 return NetGetInfo (pipe:"\srvsvc", uuid:"4b324fc8-1670-01d3-1278-5a47bf6ee188", vers:3, level:level, opnum:OPNUM_SERVERGETINFO);
}



#---------------------------------------------------------#
# Function    : NetWkstaGetInfo                           #
# Description : Return workstation information            #
# Return      : array of level info                       #
#               [0] = platform_id (DWORD)                 #
#               [1] = hostname (STRING)                   #
#               [2] = domainname (STRING)                 #
#               [3] = major (DWORD)                       #
#               [4] = minor (DWORD)                       #
#               [5] = lanroot (STRING) - level 101-102    #
#               [6] = logged users (DWORD) - level 102    #
#---------------------------------------------------------#

function NetWkstaGetInfo (level)
{
 local_var ret, level, ref_id, rep, platform_id, major, minor, pos, logged, hostname, domainname, lanrootname, actual_count;

 ret = NetGetInfo(pipe:"\wkssvc", uuid:"6bffd098-a112-3610-9833-46c3f87e345a", vers:1, level:level, opnum:OPNUM_WKSTAGETINFO);
 if (isnull(ret))
   return NULL;

 level = ret[0];
 rep = ret[1];

 if ((level != 100) && (level != 101) && (level != 102))
   return NULL;

 if (strlen(rep) < 24)
   return NULL;

 ref_id = get_dword (blob:rep, pos:0);
 platform_id = get_dword (blob:rep, pos:4);
 # server_id = get_dword (blob:rep, pos:8);
 # host_id = get_dword (blob:rep, pos:12);
 major = get_dword (blob:rep, pos:16);
 minor = get_dword (blob:rep, pos:20);
 pos = 24;
 if (level >= 101)
 {
  # lan_id = get_dword (blob:rep, pos:pos);
  pos += 4;
 }
 if (level == 102)
 {
  if (strlen(rep) < 36)
    return NULL;
  logged = get_dword (blob:rep, pos:pos);
  pos += 4;
 }

 # Wksta is unicode

 # hostname
 if (strlen(rep) < pos + 12 + 4)
   return NULL;
 actual_count = get_dword(blob:rep, pos:pos+8) * 2;
 if (strlen(rep) < pos + actual_count + 4)
   return NULL;
 hostname = get_string2 (blob:rep, pos:pos+12, len:actual_count, _type:UNICODE_STRING);
 pos += actual_count + 12;
 if (actual_count%4)
   pos += 2;

 # Domain name
 if (strlen(rep) < pos + 12 + 4)
   return NULL;
 actual_count = get_dword(blob:rep, pos:pos+8) * 2;
 if (strlen(rep) < pos + actual_count + 4)
   return NULL;
 domainname = get_string2 (blob:rep, pos:pos+12, len:actual_count, _type:UNICODE_STRING);
 pos += actual_count + 12;
 if (actual_count%4)
   pos += 2;

 if (level >= 101)
 {
  # Lan root
  if (strlen(rep) < pos + 12 + 4)
    return NULL;
  actual_count = get_dword(blob:rep, pos:pos+8) * 2;
  if (strlen(rep) < pos + actual_count + 4)
    return NULL;
  lanrootname = get_string2 (blob:rep, pos:pos+12, len:actual_count, _type:UNICODE_STRING);
  pos += actual_count + 12;
  if (actual_count%4)
    pos += 2;
 }

 ret = NULL;
 ret[0] = platform_id;
 ret[1] = hostname;
 ret[2] = domainname;
 ret[3] = major;
 ret[4] = minor;
 if (level >= 101)
   ret[5] = lanrootname;
 if (level == 102)
   ret[6] = logged;

 return ret;
}


#---------------------------------------------------------#
# Function    : NetSessionEnum                            #
# Description : Return session information                #
#---------------------------------------------------------#

function NetSessionEnum (level, computer, user)
{
 local_var fid, name, len, data, rep, resp, ret, comp, _user;

 if (!isnull(computer))
  comp = class_parameter (ref_id:0x00020004, name:computer);
 else
  comp = raw_dword (d:0);

 if (!isnull(user))
  _user = class_parameter (ref_id:0x00020008, name:user);
 else
  _user = raw_dword (d:0);
   

 fid = bind_pipe (pipe:"\srvsvc", uuid:"4b324fc8-1670-01d3-1278-5a47bf6ee188", vers:3);

 data = class_parameter (ref_id:0x00020000, name:"\"+session_get_hostname()) +
        comp                     + # computer name
        _user                    + # user name
	raw_dword (d:level)      + # Info level
        
        # share info container
        raw_dword (d:level)      + # Share Info level (multi share request with different level ?)
        raw_dword (d:0x00020004) + # Referent ID
        raw_dword (d:0)          + # number of entries
        raw_dword (d:0)          + # share info array (NULL)

        raw_dword (d:0xFFFFFFFF) + # preferred length
        
        # Enum handle
        buffer_parameter (ref_id:0x00020008, size:0);

 data = dce_rpc_pipe_request (fid:fid, code:OPNUM_NETSESSENUM, data:data);
 if (!data)
 {
   smb_close (fid:fid);
   return NULL;
 }

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) < 24))
 {
  smb_close (fid:fid);
  return NULL;
 }

 resp = get_dword (blob:rep, pos:strlen(rep) - 4);
 if (resp != STATUS_SUCCESS)
 {
  smb_close (fid:fid);
  return NULL;
 }

 ret = substr (rep, 0, strlen(rep)-4-1);

 smb_close (fid:fid);
 
 return ret;
}


#---------------------------------------------------------#
# Function    : NetShareEnum                              #
# Description : Return host's shares information          #
# level       : SHARE_INFO_x (x = 0, 1, 2, 502)           #
#---------------------------------------------------------#

function NetShareEnum (level)
{
 local_var rep, info_level, ref_id, num, max_count, actual_count, name, pos, shares, i, offset, comment;

 rep = NetEnum (pipe:"\srvsvc", uuid:"4b324fc8-1670-01d3-1278-5a47bf6ee188", vers:3, level:level, opnum:OPNUM_SHAREENUM);
 if (!rep || (strlen (rep) < 24))
   return NULL;

 shares = NULL;

 info_level = get_dword (blob:rep, pos:0);
 
 if (info_level == SHARE_INFO_0)
 {
  info_level = get_dword (blob:rep, pos:4);
  ref_id = get_dword (blob:rep, pos:8);
  num = get_dword (blob:rep, pos:12);

  #SHARE_INFO_0 Array
  ref_id = get_dword (blob:rep, pos:16);
  max_count = get_dword (blob:rep, pos:20);

  # don't parse each share ref_id
  pos = 24 + max_count*4;

  for (i = 0; i<num; i++)
  {
   if (strlen (rep) < pos + 12)
     return NULL;

   max_count = get_dword (blob:rep, pos:pos);
   offset = get_dword (blob:rep, pos:pos+4);
   actual_count = get_dword (blob:rep, pos:pos+8);
  
   if (session_is_unicode () == 1)
     actual_count = actual_count * 2;

   if (strlen (rep) < pos + 12 + actual_count)
     return NULL;

   name = get_string2 (blob:rep, pos:pos + 12, len:actual_count);
  
   pos += actual_count + 12;

   while ((actual_count % 4) != 0)
   {
    actual_count ++;
    pos ++;
   }

   shares[i] = name;
  }
 }

 return shares;
}



#---------------------------------------------------------#
# Function    : NetWkstaUserEnum                          #
# Description : Return logged users                       #
# level       : WKSTA_USER_INFO_x (x = 0, 1)              #
#---------------------------------------------------------#

function NetWkstaUserEnum (level)
{
 return NetEnum (pipe:"\wkssvc", uuid:"6bffd098-a112-3610-9833-46c3f87e345a", vers:1, level:level, opnum:OPNUM_WKSTAUSERENUM);
}



#---------------------------------------------------------#
# Function    : NetServerEnum                             #
# Description : Return enumerated systems                 #
# Return      : return Array                              #
#---------------------------------------------------------#
#                                                         #
# If level == 0, array item is an ascii string.           #
#                                                         #
# If level == 1, array item is the following structure    #
#                                                         #
#   byte [16] server name                                 #
#   byte os_vers_major                                    #
#   byte os_vers_minor                                    #
#   DWORD server_type                                     #
#   byte [] comment (not null terminated)                 #
#                                                         #
#---------------------------------------------------------#

function NetServerEnum (level)
{
 local_var data, resp, convert, count, available, ret, i, offset, comment;

 data = raw_word (w:104)         + # Function code
        ascii (string:"WrLehDO") + # Parameter Descriptor
	ascii (string:"B16BBDz") + # Return Descriptor
	raw_word (w:level)       + # Detail level
	raw_word (w:0xFFFF)      + # Receive buffer length
	raw_dword (d:3) ;          # Server type (server + workstation)

 data = smb_trans_lanman (data:data);
 if (!data || (strlen(data) < 8))
   return NULL;

 # WORD status
 # WORD convert
 # WORD Entry count
 # WORD Available entries

 resp = get_word (blob:data, pos:0);
 convert = get_word (blob:data, pos:2);
 count = get_word (blob:data, pos:4);
 available = get_word (blob:data, pos:6);

 if (resp != STATUS_SUCCESS)
   return NULL;

 if (level == 0)
 {
  # struct :
  # byte [16] server_name;

  if (strlen (data) < (8 + count*16))
    return NULL;
  ret = NULL;
  for (i=0; i<count; i++)
  {
   ret[i] = get_string (blob:data, pos:8+i*16, _type:ASCII_STRING);
  }
 }
 else
 {
  # struct :
  # byte [16] server name
  # byte os_vers_major
  # byte os_vers_minor
  # DWORD server_type
  # DWORD comment_offset

  if (strlen (data) < (8 + count*26))
    return NULL;
  ret = NULL;
  for (i=0; i<count; i++)
  {
   # offset is a negative position at the end of the buffer
   offset = 65535 - get_dword (blob:data, pos:8+i*26+22);
   offset = strlen(data) - offset - 1;
   if ((offset > 0) && (offset < strlen(data)))
     comment = get_string (blob:data, pos:offset, _type:ASCII_STRING);
   else
     comment = "";
   ret[i] = substr (data, 8+i*26, 8+i*26+25) + comment;
  }  
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : NetUserGetGroups                          #
# Description : Return user's group                       #
#---------------------------------------------------------#

function NetUserGetGroups (user)
{
 local_var ret, handle, domains, sid, handle2, rid, uhandle, rids;

 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  domains = SamEnumerateDomainsInSamServer (handle:handle);
  if (!isnull(domains))
  {
   sid = SamLookupDomainInSamServer (handle:handle, domain:domains[0]);
   if (!isnull(sid))
   {
    handle2 = SamOpenDomain (handle:handle, sid:sid, access:0x200);
    if (!isnull (handle2))
    {
     rid = SamLookupNamesInDomain (handle:handle2, user:user);
     if (!isnull(rid))
     {
      uhandle = SamOpenUser (handle:handle2, rid:rid, access:0x100);
      if (!isnull(uhandle))
      {
       rids = SamGetGroupsForUser (handle:uhandle);
       if (!isnull (rids))
       #  ret = SamLookupIdsInDomain (handle:handle2, ids:rids);
         ret = rids;

       SamCloseHandle(handle:uhandle);
      }
     }
    }

    SamCloseHandle(handle:handle2);
   }
  }

  SamCloseHandle(handle:handle);
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : NetUserGetLocalGroups                     #
# Description : Return user's local group                 #
#---------------------------------------------------------#

function NetUserGetLocalGroups (user)
{
 local_var ret, handle, domains, sid, handle2, rid, uhandle, rids, builtsid, handle3, aliases;

 builtsid = raw_string (0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00);
 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  domains = SamEnumerateDomainsInSamServer (handle:handle);
  if (!isnull(domains))
  {
   sid = SamLookupDomainInSamServer (handle:handle, domain:domains[0]);
   if (!isnull(sid))
   {
    handle2 = SamOpenDomain (handle:handle, sid:sid, access:0x280);
    if (!isnull (handle2))
    {
     handle3 = SamOpenDomain (handle:handle, sid:builtsid, access:0x280);
     if (!isnull (handle3))
     {
      rid = SamLookupNamesInDomain (handle:handle2, user:user);
      if (!isnull(rid))
      {
       uhandle = SamOpenUser (handle:handle2, rid:rid, access:0x100);
       if (!isnull(uhandle))
       {
        rids = SamGetGroupsForUser (handle:uhandle);
        if (!isnull (rids))
        {
          aliases = SamGetAliasMemberShip (handle:handle2, sid:sid, rids:rids, urid:rid);
          if (isnull(aliases))
            aliases = SamGetAliasMemberShip (handle:handle3, sid:sid, rids:rids, urid:rid);

          if (!isnull(aliases))
          #  ret = SamLookupIdsInDomain (handle:handle2, ids:rids);
          ret = aliases;
        }

        SamCloseHandle(handle:uhandle);
       }
      }
     }
    }

    SamCloseHandle(handle:handle2);
   }
  }

  SamCloseHandle(handle:handle);
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : NetLocalGroupGetMembers                   #
# Description : Return local group members                #
#---------------------------------------------------------#

function NetLocalGroupGetMembers (group)
{
 local_var ret, handle, domains, sid, handle2, rid, handle3, names, lsa, members, builtsid;

 builtsid = raw_string (0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00);
 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  handle2 = SamOpenDomain (handle:handle, sid:builtsid, access:0x200);
  if (!isnull (handle2))
  {
   rid = SamLookupNamesInDomain (handle:handle2, user:group);
   if (!isnull(rid))
   {
    handle3 = SamOpenAlias (handle:handle2, rid:rid, access:0x2000C);
    if (!isnull(handle3))
    {
     members = SamGetMembersInAlias (handle:handle3);
     if (!isnull(members))
     {
      lsa = LsaOpenPolicy (desired_access:0x20801);
      if (!isnull(lsa))
      {
       names = LsaLookupSid (handle:lsa, sid_array:members);
       if (!isnull(names))
       {
        ret = names;
       }

       LsaClose (handle:lsa);
      }
     }

     SamCloseHandle(handle:handle3);
    }
   }

   SamCloseHandle(handle:handle2);
  }

  SamCloseHandle(handle:handle);
 }

 return ret;
}



#---------------------------------------------------------#
# Function    : NetGroupGetUsers                          #
# Description : Return group members                      #
#---------------------------------------------------------#

function NetGroupGetUsers (group)
{
 local_var ret, handle, domains, sid, handle2, rid, ghandle, members;

 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  domains = SamEnumerateDomainsInSamServer (handle:handle);
  if (!isnull(domains))
  {
   sid = SamLookupDomainInSamServer (handle:handle, domain:domains[0]);
   if (!isnull(sid))
   {
    handle2 = SamOpenDomain (handle:handle, sid:sid, access:0x200);
    if (!isnull (handle2))
    {
     rid = SamLookupNamesInDomain (handle:handle2, user:group);
     if (!isnull(rid))
     {
      ghandle = SamOpenGroup (handle:handle2, rid:rid, access:0x10);
      if (!isnull(ghandle))
      {
       members = SamGetMembersInGroup (handle:ghandle);
       if (!isnull(members))
       {
         ret = SamLookupIdsInDomain (handle:handle2, ids:members);
       }
       
       SamCloseHandle(handle:ghandle);
      }
     }
    }

    SamCloseHandle(handle:handle2);
   }
  }
  
  SamCloseHandle(handle:handle);
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : NetUserGetInfo                            #
# Description : Return user's info                        #
#---------------------------------------------------------#

function NetUserGetInfo (user)
{
 local_var ret, handle, domains, sid, handle2, rid, uhandle;

 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  domains = SamEnumerateDomainsInSamServer (handle:handle);
  if (!isnull(domains))
  {
   sid = SamLookupDomainInSamServer (handle:handle, domain:domains[0]);
   if (!isnull(sid))
   {
    handle2 = SamOpenDomain (handle:handle, sid:sid, access:0x200);
    if (!isnull (handle2))
    {
     rid = SamLookupNamesInDomain (handle:handle2, user:user);
     if (!isnull(rid))
     {
      uhandle = SamOpenUser (handle:handle2, rid:rid, access:0x11b);
      if (!isnull(uhandle))
      {
       ret = SamQueryInformationUser (handle:uhandle);
       SamCloseHandle(handle:uhandle);
      }
     }
    }

    SamCloseHandle(handle:handle2);
   }
  }
  
  SamCloseHandle(handle:handle);
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : NetUserGetModals                          #
# Description : Return password policy                    #
# Return      : if level == 1                             #
#                 ret[0] = min pass len                   #
#                 ret[1] = pass history len               #
#                 ret[2] = max pass age                   #
#                 ret[3] = min pass age                   #
#                 ret[4] = force logoff                   #
#                 ret[5] = must meet complexity           #
#               if level == 3                             #
#                 ret[0] = lockout duration               #
#                 ret[1] = lockout observation window     #
#                 ret[2] = lockout treshold               #
# Note        : time in seconds (-1 if infinite)          #
#---------------------------------------------------------#

function NetUserGetModals (level)
{
 local_var ret, handle, domains, sid, handle2, rid, uhandle, tmp;

 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  domains = SamEnumerateDomainsInSamServer (handle:handle);
  if (!isnull(domains))
  {
   sid = SamLookupDomainInSamServer (handle:handle, domain:domains[0]);
   if (!isnull(sid))
   {
    handle2 = SamOpenDomain (handle:handle, sid:sid, access:0x205);
    if (!isnull (handle2))
    {
     if (level == 1)
     {
      ret = SamQueryInformationDomain (handle:handle2, level:1);
      if (!isnull (ret))
      {
       tmp = SamQueryInformationDomain (handle:handle2, level:3);
       if (!isnull(tmp))
         ret[max_index(ret)] = tmp[0];
      }
     }
     else if (level == 3)
     {
      ret = SamQueryInformationDomain (handle:handle2, level:12);
     }
    }

    SamCloseHandle(handle:handle2);
   }
  }
  
  SamCloseHandle(handle:handle);
 }

 return ret;
}

