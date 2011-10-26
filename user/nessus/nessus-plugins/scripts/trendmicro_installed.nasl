#
# (C) Tenable Network Security
#
if(description)
{
 script_id(16192);
 script_version("$Revision: 1.267 $");
 name["english"] = "Trend Micro Anti Virus Check";
 script_name(english:name["english"]);
 desc["english"] = "
This plugin checks that the remote host has the Trend Micro AntiVirus
installed  and then makes sure the latest Vdefs are loaded.

Solution : Make sure Trend Micro Antivirus is installed and using the latest VDEFS.
Risk factor : Medium";

 script_description(english:desc["english"]);
 summary["english"] = "Checks that the remote host has Trend Micro AntiVirus installed and then makes sure the latest Vdefs are loaded."; 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security"); 
 family["english"] = "Windows"; 
 script_family(english:family["english"]);
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl", "smb_enum_services.nasl"); 
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access","SMB/transport");
 script_require_ports(139, 445); 
 exit(0);
}
include("smb_func.inc");



#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#


#-------------------------------------------------------------#
# Checks the engine version                                   #
#-------------------------------------------------------------#
function check_engine_version ()
{
  local_var key, item, key_h, value, vers;

  key = "SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc."; 
  item = "VsAPINT-Ver";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);
   RegCloseKey (handle:key_h);

   if (!isnull (value))
   {
     vers = ereg_replace (pattern:"([0-9])+\.([0-9]+)-[0-9]+", replace:"\1\2", string:value[1]);
     set_kb_item(name:"Antivirus/TrendMicro/trendmicro_engine_version", value:vers);
     return vers;
   }
  }
  
  return NULL;
}


#-------------------------------------------------------------#
# Checks the database version                                 #
#-------------------------------------------------------------#
function check_database_version ()
{
  local_var key, item, key_h, value;

  key = "SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc."; 
  item = "PatternVer"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);
   RegCloseKey (handle:key_h);

   if (!isnull (value))
     return value[1];
  }
  
  return NULL;
}


#-------------------------------------------------------------#
# Checks the database date                                    #
#-------------------------------------------------------------#
function check_database_date ()
{
  local_var key, item, key_h, value;

  key = "SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc."; 
  item = "PatternDate"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);
   RegCloseKey (handle:key_h);

   if (!isnull (value))
   {
     set_kb_item(name:"Antivirus/TrendMicro/trendmicro_engine_version", value:value[1]);
     return value[1];
   }
  }
  
  return NULL;
}


#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#
function check_product_version ()
{
  local_var key, item, key_h, value;

  key = "SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc."; 
  item = "ProgramVer"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);
   RegCloseKey (handle:key_h);

   if (!isnull (value))
     return value[1];
  }
  
  return NULL;
}



#==================================================================#
# Section 2. Main code                                             #
#==================================================================#


services = get_kb_item("SMB/svcs");
#if ( ! services ) exit(0);

access = get_kb_item("SMB/registry_full_access");
if ( ! access ) exit(0);

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
# Checks if McAfee VirusScan is installed                     #
#-------------------------------------------------------------#


key = "SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion";
item = "InstDate";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);

 if (isnull (value))
 {
  RegCloseKey (handle:hklm);
  NetUseDel ();
  exit(0);
 }

 RegCloseKey (handle:key_h);
}
else exit(0);

# Save in the registry. Can be used by another plugin
# Idea from Noam Rathaus
set_kb_item(name: "Antivirus/TrendMicro/installed", value:TRUE);


#-------------------------------------------------------------#
# Checks the engine version                                   #
#-------------------------------------------------------------#

# Take the first engine version key
current_engine_version = check_engine_version (); 


#-------------------------------------------------------------#
# Checks the database version                                 #
#-------------------------------------------------------------#

# Take the first database version key
current_database_version = check_database_version (); 


#-------------------------------------------------------------#
# Checks the database date                                    #
#-------------------------------------------------------------#

database_date = check_database_date ();


#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#

product_version = check_product_version ();


#-------------------------------------------------------------#
# Checks if Antivirus is running                              #
#-------------------------------------------------------------#

##### Is OfficeScan running for all TrenMicro products ? ######

if ( services )
{
  if("OfficeScanNT" >!< services)
    running = 0;
  else
    running = 1;
}


RegCloseKey (handle:hklm);
NetUseDel ();


#==================================================================#
# Section 3. Final Report                                          #
#==================================================================#

# var initialization
warning = 0;

#
# We first report informations about the antivirus
#
report = "
The remote host has the Trend Micro AntiVirus installed.
It has been fingerprinted as :

Trend Micro AntiVirus : " + product_version + "
Engine version : " + current_engine_version + "
Virus Def version : " + current_database_version + "
Updated date : " + database_date + "

";


#
# Check if antivirus engine is up-to-date
#

# Last Engine Version
last_engine_version = "8320";

# Last Engine Version is 7.100-1003

if (int(current_engine_version) < int(last_engine_version))
{
  report += "The remote host has an out-dated version of the Trend Micro
virus engine. Last version is " + last_engine_version + "

";
  warning = 1;
}



#
# Check if antivirus database is up-to-date
#

# Last Database Date
datevers="20061029";

if ( int(database_date) < ( int(datevers) - 1 ) )
{
  report += "The remote host has an out-dated version of the Trend Micro
virus database. Last version is " + datvers + "

";
  warning = 1;
}




#
# Check if antivirus is running
#

if (services && !running)
{
  report += "The remote Trend Micro AntiVirus is not running.

";
  warning = 1;
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
  set_kb_item (name:"Antivirus/TrendMicro/description", value:report);
}

