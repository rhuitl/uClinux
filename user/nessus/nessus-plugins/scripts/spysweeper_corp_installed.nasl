#
# This script has been rewritten by Montgomery County
# Original script was written by Jeff Adams <jeffadams@comcast.net>
# and Tenable Network Security
# This script is released under GPLv2
#
if(description)
{
 script_id(21726);
 script_version("$Revision: 1.38 $");
 name["english"] = "Webroot SpySweeper Enterprise Check";

 script_name(english:name["english"]);
 desc["english"] = "
This plugin checks that the remote host has Webroot Spy Sweeper 
Enterprise installed and properly running, and makes sure that the latest 
Vdefs are loaded.

Solution : Make sure Spy Sweeper Ent is installed, running and using the 
latest VDEFS.
Risk factor : High";

 script_description(english:desc["english"]);
 summary["english"] = "Checks that SpySweeper is installed and then makes sure the latest Vdefs are loaded."; 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2005 Jeff Adams / Tenable Network Security"); 
 family["english"] = "Windows"; 
 script_family(english:family["english"]);
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl", "smb_enum_services.nasl"); 
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport");
 script_require_ports(139, 445); 
 exit(0);
}
include("smb_func.inc");


#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#


#-------------------------------------------------------------#
# Checks the virus signature version                          #
#-------------------------------------------------------------#
function check_signature_version ()
{
  local_var key, item, key_h, value, path, vers;

  key = "SOFTWARE\Webroot\Enterprise\CommAgent\"; 
  item = "sdfv"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  value = RegQueryValue(handle:key_h, item:item);  

  RegCloseKey (handle:key_h);   

  set_kb_item(name: "Antivirus/SpySweeperEnt/signature", value:value[1]);
  return value[1];
}


#-------------------------------------------------------------#
# Checks the product version                                  #
# Ugh -- the only way to determine product version is to look #
# within SpySweeper.exe.                                      #
#-------------------------------------------------------------#
function check_product_version ()
{
  local_var key, item, key_h, value;

  key = "SOFTWARE\Webroot\Enterprise\Spy Sweeper";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
      value = RegQueryValue(handle:key_h, item:"id");
    if (!isnull(value)) path = value[1];
      else path = NULL;

    RegCloseKey(handle:key_h);
  }
  else path = NULL;

  RegCloseKey(handle:hklm);

  if (isnull(path)) {
    NetUseDel();
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  exe = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\SpySweeperUI.exe", string:path);

  conn = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (conn != 1) {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (isnull(fh))
  {
    NetUseDel();
    exit(0);
  }

  version = GetFileVersion(handle:fh);
  CloseFile(handle:fh);

  if (isnull(version))
  {
    ver = "Unable to determine version";
    set_kb_item(name: "Antivirus/SpySweeperEnt/version", value:ver);
    NetUseDel();
    exit(0);
  }

   ver = string(version[0], ".", version[1], ".", version[2], ".", version[3]);
   set_kb_item(name: "Antivirus/SpySweeperEnt/version", value:ver);

   return ver;
}


#==================================================================#
# Section 2. Main code                                             #
#==================================================================#


services = get_kb_item("SMB/svcs");
#if ( ! services ) exit(0);

access = get_kb_item("SMB/registry_full_access");
if( ! access )exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) ) 
{
 NetUseDel();
 exit(0);
}

#-------------------------------------------------------------#
# Checks if Spy Sweeper Enterprise is installed               #
#-------------------------------------------------------------#

value = NULL;

key = "SOFTWARE\Webroot\Enterprise\Spy Sweeper\";
item = "id";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 RegCloseKey (handle:key_h);
}

if ( isnull ( value ) )
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);  
}

set_kb_item(name: "Antivirus/SpySweeperEnt/installed", value:TRUE);


#-------------------------------------------------------------#
# Checks if Spy Sweeper Enterprise has Parent server set      #
#-------------------------------------------------------------#

value = NULL;

key = "SOFTWARE\Webroot\Enterprise\CommAgent\";
item = "su";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 RegCloseKey (handle:key_h);
}

if ( strlen (value[1]) <=1 )
{
  set_kb_item(name: "Antivirus/SpySweeperEnt/noparent", value:TRUE);
  RegCloseKey(handle:hklm);
}
else
{
  set_kb_item(name: "Antivirus/SpySweeperEnt/parent", value:value[1]);
}

#-------------------------------------------------------------#
# Checks the virus signature version                          #
#-------------------------------------------------------------#
current_signature_version = check_signature_version (); 


#-------------------------------------------------------------#
# Checks if Spy Sweeper is running                            #
# Both of these need to running in order to ensure proper     #
# operation.                                                  # 
#-------------------------------------------------------------#

if ( services )
{
  if (("WebrootSpySweeperService" >!< services) || ("Webroot CommAgent Service" >!< services))
    running = 0;
  else
    running = 1;
}


#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#
product_version = check_product_version ();


#-------------------------------------------------------------#
# Section 3. Clean up                                         #
#-------------------------------------------------------------#

RegCloseKey (handle:hklm);
NetUseDel();

#==================================================================#
# Section 4. Final Report                                          #
#==================================================================#

# var initialization
warning = 0;

#
# We first report informations about the antivirus
#
report = "
The remote host has the Webroot Spy Sweeper Enterprise installed. It has 
been fingerprinted as :

";

report += "Spy Sweeper Enterprise " + product_version + "
DAT version : " + current_signature_version + "

";

#
# Check if antivirus signature is up-to-date
#

# Last Database Version
# Updates are located here:
# http://www.webroot.com/entcenter/index.php
virus = "790";

if ( int(current_signature_version) < int(virus) )
{
  report += "The remote host has an out-dated version of the Spy 
Sweeper virus signatures. Last version is " + virus + "

";
  warning = 1;
}


#
# Check if antivirus is running
#

if (services && !running)
{
  report += "The remote Spy Sweeper Enterprise is not running.

";
  set_kb_item(name: "Antivirus/SpySweeperEnt/running", value:FALSE);
  warning = 1;
}
else
{
  set_kb_item(name: "Antivirus/SpySweeperEnt/running", value:TRUE);
}

#
# Create the final report
#

if (warning)
{
  report += "As a result, the remote host might be infected by spyware 
received by browsing or other means.";

  report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		report);

  security_hole(port:port, data:report);
}
else
{
  set_kb_item (name:"Antivirus/SpySweeperEnt/description", value:report);
}
