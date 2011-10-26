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
# smb_hotfixes_fcheck.inc
# $Revision: 1.14 $


HCF_CONNECT = -1;	# Could not connect to port 139 or 445
HCF_NOAUTH =  -2;	# No credentials or share does not exist
HCF_NOENT  =  -3;	# File does not exist
HCF_ERR    =  -4;       # Unknown error
HCF_OK	   =   0;  	# No error
HCF_OLDER  =   1;	# The remote file is older than what we wanted	


HCF_UNACCESSIBLE_SHARE = 2;
HCF_ACCESSIBLE_SHARE   = 3;

global_var hcf_init;


function hotfix_check_fversion_init()
{
 local_var soc, port, name;

 port = kb_smb_transport(); 
 name = kb_smb_name();
 soc = open_sock_tcp(port);
 if  ( ! soc ) return HCF_CONNECT;

 session_init(socket:soc, hostname:name);
 hcf_init = 1;
 return HCF_OK;
}


function hotfix_check_fversion_end()
{
 if ( hcf_init != 0 ) {
	NetUseDel(); 
	hcf_init = 0;
	}
 return HCF_OK;
}




function hotfix_check_fversion(file, version, path, min_version)
{
 local_var login, pass, domain, share, r, handle, v, str_v,v2, i, backslash;

 if ( hcf_init == 0 ) 
	{
		if ( hotfix_check_fversion_init() != HCF_OK ) return 0;
	}


 if ( isnull(path) )
  path = hotfix_get_systemroot();

  if ( isnull(path) ) return HCF_ERR;

 
 share = ereg_replace(pattern:"^([A-Z]):.*", string:path, replace:"\1$");
 if ( file[0] == "\" || ( strlen(path) > 0 && path [ strlen(path) - 1 ] == "\") ) 
      backslash = "";
 else
      backslash = "\";

 file = ereg_replace(pattern:"^[A-Z]:(.*)", string:path, replace:"\1" + backslash + file);

 # Get the file version

 str_v = get_kb_item("SMB/FileVersions" + tolower(str_replace(string:file, find:"\", replace:"/")));
 if ( ! isnull(str_v) )
 {
  v2 = split( str_v, sep:'.', keep:0);
  v = make_list(v2[0], v2[1], v2[2], v2[3]);
 }
 else  
 {
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();


  r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if ( r != 1 ) return HCF_NOAUTH;

  handle = CreateFile(file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
  if ( isnull(handle) ) return HCF_NOENT;
 
  v = GetFileVersion(handle:handle);
  CloseFile(handle:handle);
  set_kb_item(name:"SMB/FileVersions" + tolower(str_replace(string:file, find:"\", replace:"/")), value:v[0] + "." + v[1] + "." + v[2] + "." + v[3]);
 }

 if ( isnull(min_version) )
	min_version = make_list(0,0,0,0);
 else {
	min_version = split(min_version, sep:'.', keep:0);
	min_version = make_list(int(min_version[0]), int(min_version[1]), int(min_version[2]), int(min_version[3]));
     }

 version = split(version, sep:'.', keep:0);
 version = make_list(int(version[0]), int(version[1]), int(version[2]), int(version[3]));
 
 for ( i = 0; i < max_index(version) ; i ++ )
 {
  if ( (v[i] < version[i]) )
	{
	 if ( v[i] < min_version[i] ) return HCF_OK;
	 else return HCF_OLDER;
	}
  else if (v[i] > version[i])
    return HCF_OK;
 }

 return HCF_OK;
}

function hotfix_is_vulnerable(os, sp, file, version, dir, path, min_version)
{
 local_var r;
 local_var my_sp, my_os;


 my_os = get_kb_item("SMB/WindowsVersion");
 my_sp = get_kb_item("SMB/CSDVersion");
 if ( my_sp )
 {
  my_sp = ereg_replace(pattern:".*Service Pack ([0-9]).*", string:my_sp, replace:"\1");
  my_sp = int(my_sp);
 }
 else my_sp = 0;

 if ( os >!< my_os ) return 0;
 if ( ! isnull(sp) && my_sp != sp ) return 0;


 r = hotfix_check_fversion(file:dir + "\" + file, version:version, path:path, min_version:min_version);
 if ( r == HCF_OLDER) 
	return 1;
 else 
	return 0;
}


function is_accessible_share(share)
{
 local_var login, pass, domain, r;

 if (isnull(share))
 {
  share = hotfix_get_systemroot();
  if ( ! share ) return 0;
  share = ereg_replace(pattern:"^([A-Z]):.*", string:share, replace:"\1$");
 } 

  r =  get_kb_item("SMB/AccessibleShare/" + share);
  if ( r == HCF_UNACCESSIBLE_SHARE ) return 0; # Not Accessible
  else if ( r == HCF_ACCESSIBLE_SHARE ) return 1;
  
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();


  if ( hcf_init == 0 ) hotfix_check_fversion_init();
  r = NetUseAdd(login:login, password:pass, domain:domain, share:share);

  if ( r != 1 ) 
	{
	 hotfix_check_fversion_end();
	 r = HCF_UNACCESSIBLE_SHARE;
	}
  else 
	{
  	 NetUseDel(close:FALSE);
	 r = HCF_ACCESSIBLE_SHARE;
	}

  if ( defined_func("replace_kb_item") ) 
	replace_kb_item(name:"SMB/AccessibleShare/" + share, value:r);
  else
	set_kb_item(name:"SMB/AccessibleShare/" + share, value:r);

  if (r == HCF_ACCESSIBLE_SHARE)
    return 1;
  else
    return 0;
}


function hotfix_path2share(path)
{
 return ereg_replace(pattern:"^([A-Z]):.*", string:"\1$");
}
