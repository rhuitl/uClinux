#
# (C) Tenable Network Security
#



if(description)
{
 script_id(18049);
 script_cve_id("CVE-2005-1168");
 script_bugtraq_id(13167, 13173, 13174);
 script_version("$Revision: 1.5 $");

 name["english"] = "MusicMatch Multiple Vulnerabilities";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running MusicMatch, a music player.

The remote version of this software is vulnerable to a buffer
overflow condition as well as a cross site scripting vulnerability.

An attacker may exploit these flaws to execute arbitrary code on
the remote host.

See also : http://www.musicmatch.com/info/user_guide/faq/security_updates.htm
Solution : Upgrade to MusicMatch 10.0.2048 or 9.0.5066.
Risk Factor : High";

 script_description(english:desc["english"]);
 summary["english"] = "Checks for the version of MusicMatch";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"]= "Windows";
 script_family(english:family["english"]);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

# start script

include("smb_func.inc");
include("smb_hotfixes.inc");

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);
name = kb_smb_name();
port = kb_smb_transport();
if(!get_port_state(port)) exit(1);
login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();
          
soc = open_sock_tcp(port);
if(!soc) exit(1);

session_init(socket:soc, hostname:name);

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}

key = "SOFTWARE\MusicMatch\MusicMatch JukeBox";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

info = RegQueryInfoKey(handle:key_h);
for ( i = 0 ; i < info[1] ; i ++ )
{
 entries[i] = RegEnumKey(handle:key_h, index:i);
}

RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel();

max_version[0] = max_version[1] = max_version[2] = 0;

foreach entry (entries)
{
 if ( ereg(pattern:"[0-9]*\.[0-9]*\.[0-9]*", string:entry) )
 {
  version = split(entry, sep:'.', keep:0);
  if ( int(version[0]) > int(max_version[0]) ||
       (int(version[0]) == int(max_version[0]) && int(version[1]) > int(max_version[1])) ||
       (int(version[0]) == int(max_version[0]) && int(version[1]) == int(max_version[1]) && int(version[2]) > int(max_version[2])) 
     )
	{
	 max_version[0] = version[0];
	 max_version[1] = version[1];
	 max_version[2] = version[2];
	}
 }
}

if ( max_version[0] < 9 ) security_hole(0); # Versions older than 9.x were not patched
else if ( max_version[0] == 9 && max_version[2] < 5066 ) security_hole(port); # < 9.0.5066
else if ( max_version[0] == 10 && max_version[2] < 2048) security_hole(port); # < 10.0.2048

set_kb_item(name:"SMB/MusicMatch/Version", value:max_version[0] + "." + max_version[1] + "." + max_version[2]);

