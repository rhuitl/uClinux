#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14835);
 script_version("$Revision: 1.5 $");

 name["english"] = "Symantec Norton AntiVirus Version Detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
This script determines the version of the remote Norton AntiVirus as
written in the registry of the remote host.

Risk Factor : None";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of the remote NAV";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

if ( get_kb_item("SMB/samba") ) exit(0);
if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(0);
include("smb_func.inc");



name = kb_smb_name();
port = kb_smb_transport();
if(!get_port_state(port)) exit(1);
login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();

	  
soc = open_sock_tcp(port);
if(!soc) exit(0);

session_init(socket:soc, hostname:name);

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) ) 
{
 NetUseDel();
 exit(1);
}

# Corporate Edition
key = "SOFTWARE\Symantec\Symantec AntiVirus\Install";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
  info = RegQueryInfoKey(handle:key_h);
  for ( i = 0 ; i < info[1]; i ++ )
  {
   entries[i] = RegEnumKey(handle:key_h, index:i);
   if ( ! entries[i] ) break;
  }
  RegCloseKey(handle:key_h);
  # Try to find the newest entry
  i_maj_max = 0;
  i_min_max = 0;
  foreach version (entries)
  {
  v = split(version, sep:".", keep:0);
  if ( int(v[0]) >= i_maj_max )
  {
    if ( i_maj_max != int(v[0]) ) i_min_max = 0;
    i_maj_max = int(v[0]);
    if ( int(v[1]) >= i_min_max ) i_min_max = int(v[1]);
  }
 }
 if ( i_maj_max ) set_kb_item(name:"SymantecNortonAntiVirus/Corporate/Version", value:string(i_maj_max, ".", i_min_max));

 security_note(port:port, data:"The remote host has Symantec Norton Antivirus Coporate Edition version " + string(i_maj_max, ".", i_min_max) + " installed");

 RegCloseKey(handle:hklm);
 NetUseDel(); 
 exit(0);
}



# "Regular" edition
key = "SOFTWARE\Symantec\Norton AntiVirus";
item = "version";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 if ( !isnull(value) )
	{
	version = value[1];
 	 set_kb_item(name:"SymantecNortonAntiVirus/Version", value:version);
 	 security_note(port:port, data:"The remote host has Symantec Norton Antivirus version " + version + " installed");
	}

 RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel();
