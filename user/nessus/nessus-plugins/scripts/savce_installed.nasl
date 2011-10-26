#
# This script has been rewritten by Montgomery County
# Original script was written by Jeff Adams <jeffadams@comcast.net>
# and Tenable Network Security
# This script is released under GPLv2
#
if(description)
{
 script_id(21725);
 script_version("$Revision: 1.52 $");
 name["english"] = "Symantec Anti Virus Corporate Edition Check";

 script_name(english:name["english"]);
 desc["english"] = "
This plugin checks that the remote host has Symantec AntiVirus 
Corporate installed and properly running, and makes sure that the latest 
Vdefs are loaded.

Solution : Make sure SAVCE is installed, running and using the latest 
VDEFS.
Risk factor : High";

 script_description(english:desc["english"]);
 summary["english"] = "Checks that SAVCE installed and then makes sure the latest Vdefs are loaded."; 
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

  key = "SOFTWARE\Symantec\SharedDefs\"; 
  item = "DEFWATCH_10"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);  
   if (!isnull (value))
     vers = value[1];
   else
   {
    item = "NAVCORP_70"; 
    value = RegQueryValue(handle:key_h, item:item);  
    if (!isnull (value))
      vers = value[1];
    else
    {
     item = "NAVNT_50_AP1"; 
     value = RegQueryValue(handle:key_h, item:item);  
     if (isnull (value))
     {
      RegCloseKey (handle:key_h);
      return NULL;    
     }
     else
       vers = value[1];
    }    
   }
   
   RegCloseKey (handle:key_h);   
  }

  key = "SOFTWARE\Symantec\InstalledApps\"; 
  item = "AVENGEDEFS"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);  
   if (!isnull (value))
     path = value[1];

   RegCloseKey (handle:key_h);
  }
  vers = substr (vers, strlen(path) + 1 , strlen(vers)-5);
  set_kb_item(name: "Antivirus/SAVCE/signature", value:vers);
  return vers;
}


#-------------------------------------------------------------#
# Checks the product version                                  #
# Note that major version will only be reported (ie. 9.0.1000 #
#    instead of 9.0.5.1000)                                   #
# Also you can check ProductVersion in                        #
#    HKLM\SOFTWARE\INTEL\LANDesk\VirusProtect6\CurrentVersion #
#-------------------------------------------------------------#
function check_product_version ()
{
  local_var key, item, key_h, value, directory, output;

  key = "SOFTWARE\Symantec\InstalledApps\"; 
  item = "NAVNT"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

  dir = RegQueryValue(handle:key_h, item:item);
  RegCloseKey (handle:key_h);

  directory = dir[1];
  key = "SOFTWARE\INTEL\DLLUsage\VP6\"; 
  item = directory + "Rtvscan.exe"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   version = RegQueryValue(handle:key_h, item:item);

   if (isnull (version))
   {
     item = directory + "Rtvscan"; 
     version = RegQueryValue(handle:key_h, item:item);
   }

   RegCloseKey (handle:key_h);

   if (!isnull (version))
   {
     set_kb_item(name: "Antivirus/SAVCE/version", value:version[1]);
     return version[1];
   }
   else
   {
     output = "Unable to determine version of " + directory;
     return output;
   }
  }
  else
  {
  output = "Unable to open directory " + directory + " v " + version[1];
  return output;
  }
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
# Checks if Symantec AntiVirus Corp is installed              #
#-------------------------------------------------------------#

value = NULL;

key = "SOFTWARE\Intel\LANDesk\VirusProtect6\CurrentVersion\";
item = "ProductVersion";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 RegCloseKey (handle:key_h);
}
else
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}

if ( isnull ( value ) )
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);  
}

set_kb_item(name: "Antivirus/SAVCE/installed", value:TRUE);


#-------------------------------------------------------------#
# Checks the virus signature version                          #
#-------------------------------------------------------------#

# Take the first signature version key
current_signature_version = check_signature_version (); 
 

#-------------------------------------------------------------#
# Checks if Antivirus is running                              #
#-------------------------------------------------------------#

# Thanks to Jeff Adams for Symantec service.
if ( services )
{
  if (("Norton AntiVirus" >!< services) && ("Symantec AntiVirus" >!< services))
    running = 0;
  else
    running = 1;
}


#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#
product_version = check_product_version();


#-------------------------------------------------------------#
# Checks if Symantec AntiVirus Corp has Parent server set     #
#-------------------------------------------------------------#

key = "SOFTWARE\Intel\LANDesk\VirusProtect6\CurrentVersion\";
item = "Parent";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 parent = RegQueryValue(handle:key_h, item:item);
 RegCloseKey (handle:key_h);
}

if ( strlen (parent[1]) <=1 )
{
  set_kb_item(name: "Antivirus/SAVCE/noparent", value:TRUE);
  RegCloseKey(handle:hklm);
}
else
{
  set_kb_item(name: "Antivirus/SAVCE/parent", value:parent[1]);
}  


#==================================================================#
# Section 3. Clean Up                                              #
#==================================================================#

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
The remote host has the Symantec Antivirus Corporate installed. It has 
been fingerprinted as :

";

report += "Symantec Antivirus Corporate " + product_version + "
DAT version : " + current_signature_version + "

";

#
# Check if antivirus signature is up-to-date
#

# Last Database Version
virus = "20061029";

if ( int(current_signature_version) < ( int(virus) - 1 ) )
{
  report += "The remote host has an out-dated version of the Symantec 
Corporate virus signatures. Last version is " + virus + "

";
  warning = 1;
}


#
# Check if antivirus is running
#

if (services && !running)
{
  report += "The remote Symantec AntiVirus Corporate is not running.

";
  set_kb_item(name: "Antivirus/SAVCE/running", value:FALSE);
  warning = 1;
}
else
{
  set_kb_item(name: "Antivirus/SAVCE/running", value:TRUE);
}

#
# Create the final report
#

if (warning)
{
  report += "As a result, the remote host might be infected by viruses received by
email or other means.";

  report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		report);

  security_hole(port:port, data:report);
}
else
{
  set_kb_item (name:"Antivirus/SAVCE/description", value:report);
}
