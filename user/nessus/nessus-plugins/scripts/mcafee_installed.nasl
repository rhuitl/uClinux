#
# This script has been rewritten by Tenable Network Security
# Original script was written by Jeff Adams <jeffadams@comcast.net>;
#

 desc["english"] = "
Synopsis :

The remote antivirus is not up to date.

Description :

The remote host is running McAfee VirusScan Antivirus. The remote
version of this software is not up to date (engine and/or virus
definitions).
It may allow an infection of the remote host by a virus or a
worm.

Solution : 

Update your virus Definitions.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if(description)
{
 script_id(12107);
 script_version("$Revision: 1.299 $");
 name["english"] = "McAfee Anti Virus Check";
 script_name(english:name["english"]);

 script_description(english:desc["english"]);
 summary["english"] = "Checks that the remote host has McAfee Antivirus installed and then makes sure the latest Vdefs are loaded."; 
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
include("http_func.inc");
include("http_keepalive.inc");

#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#


#-------------------------------------------------------------#
# Checks the engine version                                   #
#-------------------------------------------------------------#
function check_engine_version (reg)
{
  local_var key, item, key_h, version, value;

  key = reg; 
  item = "szEngineVer"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);
   RegCloseKey (handle:key_h);

   if (!isnull (value))
   {
    version = split(value[1], sep:".", keep:FALSE);
    return int(version[0]) * 1000 + int(version[1]) * 100 + int(version[2]);
   }
  }
  
  return NULL;
}


#-------------------------------------------------------------#
# Checks the database version                                 #
#-------------------------------------------------------------#
function check_database_version (reg)
{
  local_var key, item, key_h, vers, value;

  key = reg; 
  item = "szVirDefVer"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);
   if (isnull (value))
   {
    item = "szDatVersion";
    value = RegQueryValue(handle:key_h, item:item);
   }
   RegCloseKey (handle:key_h);

   if (!isnull (value))
   {
    vers = value[1];

    if ( "4.0." >< vers)
    {
      version = split(vers, sep:".", keep:FALSE);
      vers = version[2];
      return vers;
    }
    else
      return vers;
   }
  }
  
  return NULL;
}


#-------------------------------------------------------------#
# Checks the database date                                    #
#-------------------------------------------------------------#
function check_database_date (reg)
{
  local_var key, item, key_h, value;

  key = reg; 
  item = "szVirDefDate"; 
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);
   if (isnull (value))
   {
    item = "szDatDate";
    value = RegQueryValue(handle:key_h, item:item);
   }
   RegCloseKey (handle:key_h);

   if (!isnull (value))
      return value[1];
  }
  
  return NULL;
}


#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#
function check_product_version (reg)
{
  local_var key, item, key_h, value;

  key = reg; 
  item = "szProductVer"; 
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
# Checks the product name                                     #
#-------------------------------------------------------------#
function check_product_name (reg)
{
  local_var key, item, key_h, value;

  key = reg; 
  item = "Product"; 
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

key = "SOFTWARE\Network Associates\TVD\Shared Components\VirusScan Engine\4.0.xx";
item = "DAT";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

key_item = RegQueryValue(handle:key_h, item:item);
RegCloseKey(handle:key_h);
if(isnull(key_item)) 
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

value = key_item[1];

# Save in the registry. Can be used by another plugin
# Idea from Noam Rathaus
set_kb_item(name: "Antivirus/McAfee/installed", value:TRUE);


#-------------------------------------------------------------#
# Checks the engine version                                   #
#-------------------------------------------------------------#

# Take the first engine version key
engine_version1 = check_engine_version (reg:"SOFTWARE\Network Associates\TVD\Shared Components\VirusScan Engine\4.0.xx"); 

# Take the second engine version key
engine_version2 = check_engine_version (reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion"); 

# We keep the more recent version
if ( engine_version1 < engine_version2 )
  current_engine_version = engine_version2;
else
  current_engine_version = engine_version1;
 


#-------------------------------------------------------------#
# Checks the database version                                 #
#-------------------------------------------------------------#

# Initialize var
database_version1 = database_version2 = 0;

# Take the first database version key
database_version1 = check_database_version (reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion"); 

# Take the second database version key
database_version2 = check_database_version (reg:"SOFTWARE\Network Associates\TVD\Shared Components\VirusScan Engine\4.0.xx"); 

# We keep the more recent version
if ( int(database_version1) < int(database_version2) )
{
  current_database_version = database_version2;
  new_database = 0;
}
else
{
  current_database_version = database_version1;
  new_database = 1;
}


#-------------------------------------------------------------#
# Checks the database date                                    #
#-------------------------------------------------------------#

if (new_database)
  database_date = check_database_date (reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion");
else
  database_date = check_database_date (reg:"SOFTWARE\Network Associates\TVD\Shared Components\VirusScan Engine\4.0.xx");


#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#

if (new_database)
  product_version = check_product_version (reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion");
else
  product_version = NULL;


#-------------------------------------------------------------#
# Checks the product name                                     #
#-------------------------------------------------------------#

if (new_database)
  product_name = check_product_name (reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion");
else
  product_name = NULL;


#-------------------------------------------------------------#
# Checks if ePolicy Orchestror Agent is present               #
#-------------------------------------------------------------#

key = "SOFTWARE\Network Associates\ePolicy Orchestrator\Agent"; 
item = "Installed Path";

epo_installed = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (! isnull(key_h) )
{
 epo_installed = RegQueryValue(handle:key_h, item:item);
 if (!isnull(epo_installed))
   epo_installed = epo_installed[1];
 RegCloseKey(handle:key_h);
}

if (epo_installed)
  set_kb_item(name: "Antivirus/McAfee/ePO", value:TRUE);



RegCloseKey (handle:hklm);

#-------------------------------------------------------------#
# Checks if Antivirus is running                              #
#-------------------------------------------------------------#


running = 1;

sc = OpenSCManager (access_mode:SC_MANAGER_CONNECT | SC_MANAGER_QUERY_LOCK_STATUS);
if (!isnull (sc))
{
 service = OpenService (handle:sc, service:"McShield", access_mode:SERVICE_QUERY_STATUS);
 if (!isnull (service))
 {
  status = QueryServiceStatus (handle:service);
  if (!isnull (status))
  {
   if (status[1] != SERVICE_RUNNING)
     running = 0;
  }
 }
}

NetUseDel();

#==================================================================#
# Section 3. Final Report                                          #
#==================================================================#

# var initialization
warning = 0;


#
# We first report informations about the antivirus
#
report = "
The remote host has the McAfee antivirus installed. It has been
fingerprinted as :

";

if (new_database)
{
  report += product_name + " : " + product_version + "
";
}

report += "Engine version : " + current_engine_version + "
DAT version : " + current_database_version + "
Updated date : " + database_date + "
";

if (epo_installed)
{
report += "ePO Agent : installed.

";
}
else
{
report += "ePO Agent : not present.

";
}


#
# Check if antivirus engine is up-to-date
#

# Last Engine Version
last_engine_version = 4400; # 4.4.00

if (current_engine_version < last_engine_version)
{
  report += "The remote host has an out-dated version of the McAfee
virus engine. Latest version is " + last_engine_version + "

";
  warning = 1;
}



#
# Check if antivirus database is up-to-date
#

# Last Database Version
datvers="4883";

if ( int(current_database_version) < int(datvers) )
{
  report += "The remote host has an out-dated version of the McAfee
virus database. Latest version is " + datvers + "

";
  warning = 1;
}




#
# Check if antivirus is running
#

if (services && !running)
{
  report += "The remote McAffee antivirus is not running.

";
  warning = 1;
}




#
# Create the final report
#

if (warning)
{
 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		report);

 security_hole (port:port, data:report);
}
else
{
  set_kb_item (name:"Antivirus/McAfee/description", value:report);  
}

