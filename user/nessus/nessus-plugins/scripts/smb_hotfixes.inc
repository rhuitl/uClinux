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
# smb_hotfixes.inc
# $Revision: 1.22 $


include("global_settings.inc");

function hotfix_check_exchange_installed()
{
 local_var vers;

 vers = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Exchange/Setup/ServicePackBuild");
 if ( ! vers ) 
	return NULL;
 else 
	return vers;
}

function hotfix_data_access_version()
{
 local_var vers;

 vers = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/DataAccess/Version");
 if ( ! vers ) 
	return NULL;
 else 
	return vers;
}

#
# Returns Office version if it is installed, NULL if it is not
#
function hotfix_check_office_version()
{
 local_var flag;

 flag = get_kb_item("SMB/Office/Outlook");
 if ( flag )
   return flag;

 flag = get_kb_item("SMB/Office/Word");
 if ( flag )
   return flag;

 flag = get_kb_item("SMB/Office/Excel");
 if ( flag )
   return flag;

 flag = get_kb_item("SMB/Office/Powerpoint");
 if ( flag )
   return flag;

 flag = get_kb_item("SMB/Office/Publisher");
 if ( flag )
   return flag;

 return NULL;
}


#
# Returns Word version if it is installed, NULL if it is not
#
function hotfix_check_word_version()
{
 local_var flag;

 flag = get_kb_item("SMB/Office/Word");
 if ( flag )
   return flag;

 return NULL;
}

#
# Returns Excel version if it is installed, NULL if it is not
#
function hotfix_check_excel_version()
{
 local_var flag;

 flag = get_kb_item("SMB/Office/Excel");
 if ( flag )
   return flag;

 return NULL;
}

#
# Returns Powerpoint version if it is installed, NULL if it is not
#
function hotfix_check_powerpoint_version()
{
 local_var flag;

 flag = get_kb_item("SMB/Office/Powerpoint");
 if ( flag )
   return flag;

 return NULL;
}

#
# Returns Publisher version if it is installed, NULL if it is not
#
function hotfix_check_publisher_version()
{
 local_var flag;

 flag = get_kb_item("SMB/Office/Publisher");
 if ( flag )
   return flag;

 return NULL;
}

#
# Returns Outlook version if it is installed, NULL if it is not
#
function hotfix_check_outlook_version()
{
 local_var flag;

 flag = get_kb_item("SMB/Office/Outlook");
 if ( flag )
   return flag;

 return NULL;
}


function hotfix_check_ie_version()
{
 local_var flag;

 flag = get_kb_item("SMB/IE/Version");
 if ( flag )
   return flag;

 return NULL;
}


#
# Returns 1 if Works is installed, 0 if it is not
#
function hotfix_check_works_installed()
{
 local_var flag;

 flag = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Works");
 if ( ! flag ) 
	return 0;
 else
	return 1;
}



#
# Returns 1 if IIS is installed, 0 if it is not and -1 if we don't know
#
function hotfix_check_iis_installed()
{
 local_var w3svc;

 w3svc = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/W3SVC/ImagePath");
 if ( ! w3svc ) return -1;
 if ( "inetinfo" >!< w3svc )
	return 0;
 else
	return 1;
}

#
# Returns 1 if WINS is installed, 0 if it is not and -1 if we don't know
#
function hotfix_check_wins_installed()
{
 local_var wins;

 wins = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/WINS/DisplayName");
 if ( ! wins ) return -1;
 else
	return 1;
}

# Returns 1 if a DHCP server is installed, 0 if it is not and -1 if we don't know
#
function hotfix_check_dhcpserver_installed()
{

 local_var dhcp;
 dhcp = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/DHCPServer");
 if ( ! dhcp ) return -1;
 else
	return 1;
}

function hotfix_check_nt_server()
{
 local_var product_options;
 product_options = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/ProductOptions");
 if ( ! product_options ) return -1;
 if ("WinNT" >< product_options ) 
	return 0;
 else
	return 1;
}

function hotfix_check_domain_controler()
{
 local_var product_options;
 product_options = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/ProductOptions");
 if ( ! product_options ) return -1;
 if ("LanmanNT" >< product_options ) 
	return 1;
 else
	return 0;
}

function hotfix_get_mssqldir()
{
 return get_kb_item("MSSQL/Path");
}

function hotfix_get_programfilesdir()
{
 local_var str;
 str = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/ProgramFilesDir");
 return str;
}

function hotfix_get_commonfilesdir()
{
 local_var str;
 str = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/CommonFilesDir");
 return str;
}

function hotfix_get_systemroot()
{
 local_var str;
 str = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/SystemRoot");
 return str;
}

function hotfix_check_sp(nt, win2k, xp, win2003)
{
  local_var vers, sp;

  vers = get_kb_item("SMB/WindowsVersion");
  if ( ! vers ) return -1;

 

  if ( nt &&  "4.0" >< vers )
  {
    sp  = get_kb_item("SMB/CSDVersion");
    if ( sp )
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]).*", replace:"\1"));
    else
	sp = 0;

    if ( sp < nt )
 	return 1;
    else 
	return 0; 
  }   
  else if ( win2k &&  "5.0" >< vers )
  {
    sp  = get_kb_item("SMB/CSDVersion");
    if ( sp ) 
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]).*", replace:"\1"));
    else
	sp = 0;
    if ( sp < win2k )
 	return 1;
    else 
	return 0; 
  }   
  else if ( xp &&  "5.1" >< vers )
  {
    sp  = get_kb_item("SMB/CSDVersion");
    if ( sp )
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]).*", replace:"\1"));
    else
	sp = 0;
    if ( sp < xp )
 	return 1;
    else 
	return 0; 
  }   
  else if ( win2003 &&  "5.2" >< vers )
  {
    sp  = get_kb_item("SMB/CSDVersion");
    if ( sp ) 
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]).*", replace:"\1"));
    else
	sp = 0;

    if ( sp < win2003 )
 	return 1;
    else 
	return 0; 
  }   

  return -1; 
}

#-----------------------------------------------------------------------------
# hotfix_missing()
#
# Returns:
# -1 : Could not verify if the hotfix is installed (ie: lack of credentials)
#  0 : The hotfix is installed
#  1 : The hotfix is missing
#-----------------------------------------------------------------------------
function hotfix_missing(name)
{
 local_var kb, key;

 
 kb = get_kb_list("SMB/Registry/*");

 if ( isnull(kb) || max_index(make_list(keys(kb))) == 0 )
 {
   return -1;
 }

 
 # Don't get confused by QNNNNN vs KBNNNNN updates - look for both formats
 if ( "KB" >< name ) name = name - "KB";
 else if ( "Q" >< name ) name = name - "Q";
 foreach key (keys(kb))
 {
  if ( ereg(pattern:"SMB/Registry/HKLM/SOFTWARE/Microsoft/(Updates/.*|Windows NT/CurrentVersion/HotFix)/(KB|Q)" + name, string:key) )
	return 0; # The hotfix is installed
 }
  return 1; # The hotfix is indeed missing
}


