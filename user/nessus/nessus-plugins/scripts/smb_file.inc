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
# smb_file.inc
# $Revision: 1.2 $
#


#==================================================================#
# Section 8. File API                                              #
#==================================================================#



function get_win32_find_data_filename (struct)
{
 local_var len;

 if (strlen(struct) < 94)
   return NULL;

 len = get_dword (blob:struct, pos:60);
 if (strlen(struct) < 94 + len)
   return NULL;

 return get_string2 (blob:struct, pos:94, len:len);
}


function get_win32_find_data_fileattributes (struct)
{
 local_var len;

 if (strlen(struct) < 94)
   return NULL;

 return get_dword (blob:struct, pos:56);
}


#---------------------------------------------------------#
# Function    : FindFirstFile                             #
# Description : Return First file in WIN32_FIND_DATA      #
# Return      : ret[0] = file handle                      #
#               ret[1] = file name                        #
#               ret[2] = file attributes                  #
#               full handle = ret (to use with NextFile)  #
#---------------------------------------------------------#

function FindFirstFile (pattern)
{
 local_var ret, parameters, search_id, search_count, end_of_search, ea_error_offset, last_name_offset;
 local_var pad, data, index, pos, file_struct, size;

 parameters = raw_word (w:0x16)   + # Default search : include HIDDEN/SYSTEM/DIRECTORY 
              raw_word (w:0xFFFF) + # Max buffer search count
              raw_word (w:6)      + # Close if EOS is reached / RESUME
              raw_word (w:260)    + # Default level of interest
              raw_dword (d:0)     + # Storage type
              cstring (string:pattern);

 ret = smb_trans2 (param:parameters, data:NULL, max_pcount:18, command:1); 
 if (!ret || (strlen (ret) < 14))
   return NULL;

 # FIND_FIRST2 Parameters
 search_id = get_word (blob:ret, pos:0);
 search_count = get_word (blob:ret, pos:2);
 end_of_search = get_word (blob:ret, pos:4);
 ea_error_offset = get_word (blob:ret, pos:6);
 last_name_offset = get_word (blob:ret, pos:8);

 # Padding
 pad = get_word (blob:ret, pos:10);

 # FIND_FIRST2 Data
 data = substr (ret, 12, strlen(ret)-1);

 # If no data we quit
 if (search_count <= 0)
   return NULL;
 
 index = 1;
 pos = 0;
 
 # FIND_FIRST2 Data
 size = get_word (blob:data, pos:pos);
 if (strlen (data) < size)
   return NULL;
 
 file_struct = substr (data, pos, pos+size-1);

 pos += size;
 index++;

 ret = NULL;
 ret[0] = raw_word (w:search_id) +
          raw_word (w:search_count) +
          raw_word (w:end_of_search) +
          raw_word (w:index) +
          raw_dword (d:pos) +
          data;

 ret[1] = get_win32_find_data_filename (struct:file_struct);
 ret[2] = get_win32_find_data_fileattributes (struct:file_struct);

 return ret;
}



#---------------------------------------------------------#
# Function    : FindNextFile                              #
# Description : Return Next file in WIN32_FIND_DATA       #
# Return      : ret[0] = file handle                      #
#               ret[1] = file name                        #
#               full handle = ret                         #
#---------------------------------------------------------#

function FindNextFile (handle)
{
 local_var ret, parameters, search_id, search_count, end_of_search, ea_error_offset, last_name_offset;
 local_var pad, data, index, pos, file_struct, size;

 if (strlen (handle[0]) < 13)
   return NULL;

 search_id = get_word (blob:handle[0], pos:0);
 search_count = get_word (blob:handle[0], pos:2);
 end_of_search = get_word (blob:handle[0], pos:4);
 index = get_word (blob:handle[0], pos:6);
 pos = get_dword (blob:handle[0], pos:8);
 data = substr (handle[0], 12, strlen (handle[0]) - 1);

 if (index > search_count)
 {
  if (end_of_search == 1)
    return NULL;

  parameters = raw_word (w:search_id) + # Search ID
               raw_word (w:0xFFFF)    + # Max search buffer size
               raw_word (w:260)       + # Default level of interest
               raw_dword (d:0)        + # storage type
               raw_word (w:6)         + # Close if EOS is reached / RESUME
               cstring (string:handle[1]);

  ret = smb_trans2 (param:parameters, data:NULL, max_pcount:8, command:2);
  if (!ret || (strlen (ret) < 10))
    return NULL;

  # FIND_FIRST2 Parameters
  search_count = get_word (blob:ret, pos:0);
  end_of_search = get_word (blob:ret, pos:2);
  ea_error_offset = get_word (blob:ret, pos:4);
  last_name_offset = get_word (blob:ret, pos:6);

  # FIND_FIRST2 Data
  data = substr (ret, 8, strlen(ret)-1);

  # If no data we quit
  if (search_count <= 0)
    return NULL;
 
  index = 1;
  pos = 0;
 } 
 
 size = get_word (blob:data, pos:pos);
 if (strlen (data) < size)
   return NULL;

 #last elem next offset param is null
 if (size == 0)
   size = strlen (data);
 
 file_struct = substr (data, pos, pos+size-1);
 pos += size;
 index++;

 ret = NULL;
 ret[0] = raw_word (w:search_id) +
          raw_word (w:search_count) +
          raw_word (w:end_of_search) +
          raw_word (w:index) +
          raw_dword (d:pos) +
          data;


 ret[1] = get_win32_find_data_filename (struct:file_struct);
 ret[2] = get_win32_find_data_fileattributes (struct:file_struct);

 return ret;
}



#---------------------------------------------------------#
# Function    : CreateFile                                #
# Description : open a file                               #
#               return file handle                        #
#---------------------------------------------------------#

function CreateFile (file, desired_access, file_attributes, share_mode, create_disposition)
{
 return smb_create_and_x (name:file,
                          desired_access:desired_access,
                          flags_attributes:file_attributes,
                          share_mode:share_mode,
                          create_disposition:create_disposition,
                          create_options:0);
}



#---------------------------------------------------------#
# Function    : ReadFile                                  #
# Description : Read data from file                       #
#---------------------------------------------------------#

function ReadFile (handle, offset, length)
{
 local_var fid;

 fid = handle[0];

 return smb_read_and_x (fid:fid, offset:offset, length:length);
}



#---------------------------------------------------------#
# Function    : WriteFile                                 #
# Description : write data into file                      #
#---------------------------------------------------------#

function WriteFile (handle, offset, mode, data)
{
 local_var fid;

 fid = handle[0];

 return smb_write_and_x (fid:fid, offset:offset, mode:mode, data:data);
}



#---------------------------------------------------------#
# Function    : CloseFile                                 #
# Description : close a file                              #
#---------------------------------------------------------#

function CloseFile (handle)
{
 local_var fid;

 fid = handle[0];

 return smb_close (fid:fid);
}




#---------------------------------------------------------#
# Function    : GetSecurityInfo                           #
# Description : return security information               #
# Note        : only works with a file                    #
#---------------------------------------------------------#

function GetSecurityInfo (handle, level)
{
 local_var parameters, ret, len;

 parameters = raw_word (w:handle[0]) + # FID
              raw_word (w:0)         + # reserved
              raw_dword (d:level);

 ret = smb_nt_trans (param:parameters, data:NULL, command:0x06, max_pcount:4, max_dcount:0);
 if (strlen(ret) != 4)
   return NULL;

 len = get_dword (blob:ret, pos:0);
 ret = smb_nt_trans (param:parameters, data:NULL, command:0x06, max_pcount:4, max_dcount:len);
 if (strlen(ret) < 4)
   return NULL;

 len = get_dword (blob:ret, pos:0);
 if (strlen(ret) != 4 + len)
   return NULL;

 return parse_security_descriptor (blob:substr(ret, 4, strlen(ret)-1));
}


#---------------------------------------------------------#
# Function    : GetFileSize                               #
# Description : return file size                          #
#---------------------------------------------------------#

function GetFileSize (handle)
{
 local_var size;

 size = handle[1];

 # size = low DWORD + high DWORD
 # we just don't care about high DWORD for the moment
 return get_dword (blob:size, pos:0);
}



function check_version (size, offset, voffset, handle)
{
 local_var i, sig, ret, id, info_offset, res_dir, NumberOfNamedEntries, NumberOfIdEntries, entry, version_info, len, pos;

 # IMAGE_RESOURCE_DIRECTORY structure
 res_dir = ReadFile (handle:handle, offset:offset, length:16);
 if (!res_dir || strlen(res_dir) != 16)
   return NULL;
 
 NumberOfNamedEntries = get_word (blob:res_dir, pos:12);
 NumberOfIdEntries = get_word (blob:res_dir, pos:14);

 info_offset = 0;

 for (i = 0; i < NumberOfNamedEntries + NumberOfIdEntries; i++)
 {
  entry = ReadFile (handle:handle, offset:offset+16+i*8, length:8);
  if (!entry || strlen(entry) != 8)
    return NULL;
 
  id = get_dword (blob:entry, pos:0);
  if (id == 0x10) # VERSION_INFO structure
  {
   info_offset = get_dword (blob:entry, pos:4) - 0x80000000;
   break;
  }
 }

 if (info_offset == 0)
   return NULL;

 # VERSION : IMAGE_RESOURCE_DIRECTORY 1
 res_dir = ReadFile (handle:handle, offset:offset+info_offset, length:24);
 if (!res_dir || strlen(res_dir) != 24)
   return NULL;
 
 info_offset = get_dword (blob:res_dir, pos:20) - 0x80000000;


 # VERSION : IMAGE_RESOURCE_DIRECTORY 2
 res_dir = ReadFile (handle:handle, offset:offset+info_offset, length:24);
 if (!res_dir || strlen(res_dir) != 24)
   return NULL;
 
 info_offset = get_dword (blob:res_dir, pos:20);


 # VERSION : offset + size
 res_dir = ReadFile (handle:handle, offset:offset+info_offset, length:8);
 if (!res_dir || strlen(res_dir) != 8)
   return NULL;
 
 info_offset = get_dword (blob:res_dir, pos:0);

 # Convert Vitual address to offset
 info_offset = info_offset - voffset;

 
 # VS_VERSION_INFO
 version_info = ReadFile (handle:handle, offset:offset+info_offset, length:2);
 if (!version_info || strlen(version_info) != 2)
   return NULL;

 len = get_word (blob:version_info, pos:0);
 if (len < 58)
   return NULL;

 # VS_VERSION_INFO
 version_info = ReadFile (handle:handle, offset:offset+info_offset, length:len);
 if (!version_info || strlen(version_info) != len)
   return NULL;

 ret = NULL;
 ret['wLength']            = get_word (blob:version_info, pos:0);
 ret['wValueLength']       = get_word (blob:version_info, pos:2);
 ret['wType']              = get_word (blob:version_info, pos:4);
 ret['szKey']              = get_string (blob:version_info, pos:6, _type:1);

 pos = 6 + strlen (ret['szKey']) * 2 + 2;

 # word of padding padding
 if (strlen(ret['szKey']) % 2)
 {
  ret['Padding1'] = 0;
  pos += 2;
 }

 sig = get_dword (blob:version_info, pos:pos);
 if (sig != 0xfeef04bd)
   return NULL;

 ret['dwSignature']         = get_dword (blob:version_info, pos:pos);
 ret['dwStrucVersion']      = get_dword (blob:version_info, pos:pos+4);
 ret['dwFileVersionMS']     = get_dword (blob:version_info, pos:pos+8);
 ret['dwFileVersionLS']     = get_dword (blob:version_info, pos:pos+12);
 ret['dwProductVersionMS']  = get_dword (blob:version_info, pos:pos+16);
 ret['dwProductVersionLS']  = get_dword (blob:version_info, pos:pos+20);
 ret['dwFileFlagsMask']     = get_dword (blob:version_info, pos:pos+24);
 ret['dwFileFlags']         = get_dword (blob:version_info, pos:pos+28);
 ret['dwFileOS']            = get_dword (blob:version_info, pos:pos+32);
 ret['dwFileType']          = get_dword (blob:version_info, pos:pos+36);
 ret['dwFileSubtype']       = get_dword (blob:version_info, pos:pos+40);
 ret['dwFileDateMS']        = get_dword (blob:version_info, pos:pos+44);
 ret['dwFileDateLS']        = get_dword (blob:version_info, pos:pos+48);

 if ( NASL_LEVEL < 2204 )
   return ret;

 pos += 52;

 ret['Children'] = extract_structures (data:substr(version_info, pos, strlen(version_info)-1));

 return ret;
}

function extract_structures (data)
{
 local_var opos, pos, len, size, type, max_len, ret, name;

 ret = NULL;

 pos = 0;
 max_len = strlen(data);

 while (pos < max_len)
 {
  opos    = pos;
  len     = get_word (blob:data, pos:pos);
  size    = get_word (blob:data, pos:pos+2);
  type    = get_word (blob:data, pos:pos+4);

  name = get_string (blob:data, pos:pos+6, _type:1);
  pos = pos+6 + strlen (name) * 2 + 2;
  
  # word of padding
  if (strlen(name) % 2)
    pos += 2;

  if (size == 0)
    ret[name] = extract_structures (data:substr(data,pos,opos+len-1));
  else
  {
   # WCHAR
   if (type == 1)
     ret[name] = get_string (blob:data, pos:pos, _type:1);
   # Binary data
   else
     ret[name] = substr (data, pos, pos+size-1);
  }

  pos = opos + len;
  if (len % 4)
    pos += 2;
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : GetFileVersionEx                          #
# Description : return file version (exe,dll,...)         #
# Return      : VS_VERSION_INFO structure :               #
#                                                         #
# VS_VERSION_INFO :                                       #
#    ret['wLength'];                                      #
#    ret['wValueLength];                                  #
#    ret['wType'];                                        #
#    ret['szKey'];                                        #
#    [ret['Padding1']];                                   #
#    #VS_FIXEDFILEINFO Value;                             #
#     ret['dwSignature'];                                 #
#     ret['dwStrucVersion'];                              #
#     ret['dwFileVersionMS'];                             #
#     ret['dwFileVersionLS'];                             #
#     ret['dwProductVersionMS'];                          #
#     ret['dwProductVersionLS'];                          #
#     ret['dwFileFlagMask'];                              #
#     ret['dwFileFlags'];                                 #
#     ret['dwFileOS'];                                    #
#     ret['dwFileType'];                                  #
#     ret['dwFileSubtype'];                               #
#     ret['dwFileDateMS'];                                #
#     ret['dwFileDateLS'];                                #
#    ret['Children'];                                     #
#       --> ['StringFileInfo']                            #
#          --> ['040904B0']                               #
#             --> ['CompanyName'] = "Tenable Network Sec."#
#             --> ['FileVersion'] = "6.0.45.366"          #
#             --> ...                                     #
#       --> ['VarFileInfo']                               #
#          --> ['Translation'] = raw_string ("0904B004")  #
#                                                         #  
#                                                         #
#---------------------------------------------------------#

function GetFileVersionEx (handle)
{
 local_var dos_header, sig, e_lfanew, nt_header, number_of_sections, size_optional_header, i;
 local_var offset, size, sections, pos, idx, tmp, pattern, rsrc, r_pattern, ret, name, voffset;

 # We first parse IMAGE_DOS_HEADER
 dos_header = ReadFile (handle:handle, offset:0, length:64);
 if (!dos_header || (strlen(dos_header) != 64))
   return NULL;

 sig = substr(dos_header, 0, 1);
 if ("MZ" >!< sig)
   return NULL;

 e_lfanew = get_dword (blob:dos_header, pos:60);


 # We now parse Signature + IMAGE_FILE_HEADER
 nt_header = ReadFile (handle:handle, offset:e_lfanew, length:24);
 if (!nt_header || (strlen(nt_header) != 24))
   return NULL;

 sig = substr(nt_header, 0, 1);
 if ("PE" >!< sig)
   return NULL;

 number_of_sections = get_word (blob:nt_header, pos:6);
 size_optional_header = get_word (blob:nt_header, pos:20);

 
 # We now parse sections
 offset = e_lfanew + 24 + size_optional_header;
 size = number_of_sections * 40;
 sections = ReadFile (handle:handle, offset:offset, length:size);
 if (!sections || (strlen(sections) != size))
   return NULL;

 pos = rsrc = 0;
 r_pattern = ".rsrc" + raw_string (0,0,0);

 for (i=0; i<number_of_sections; i++)
 {
  name = substr(sections, pos, pos+7);
  size = get_dword (blob:sections, pos:pos+16);
  offset = get_dword (blob:sections, pos:pos+20);
  voffset = get_dword (blob:sections, pos:pos+12);

  if (r_pattern >< name)
  {
   rsrc = 1;
   break;
  }

  pos += 40;
 }

 # if no rsrc section left
 if (rsrc == 0)
   return NULL; 

 return check_version (size:size, offset:offset, voffset:voffset, handle:handle); 
}

#---------------------------------------------------------#
# Function    : GetFileVersion                            #
# Description : return file version (exe,dll,...)         #
# Return      : ret[0] = version 0                        #
#               ret[1] = version 1                        #
#               ret[2] = version 2                        #
#               ret[3] = version 3                        #
#---------------------------------------------------------#

function GetFileVersion (handle)
{
 local_var ret, tmp;

 ret = GetFileVersionEx (handle:handle);
 if (isnull(ret))
   return NULL;

 tmp = NULL;
 tmp[0] = ret['dwFileVersionMS'] >>> 16;
 tmp[1] = ret['dwFileVersionMS'] & 0xFFFF;
 tmp[2] = ret['dwFileVersionLS'] >>> 16;
 tmp[3] = ret['dwFileVersionLS'] & 0xFFFF;

 return tmp;
}


