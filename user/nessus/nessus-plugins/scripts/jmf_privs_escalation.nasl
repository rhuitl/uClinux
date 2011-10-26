#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
# Ref: http://sunsolve.sun.com/pub-cgi/retrieve.pl?doc=fsalert%2F54760&zone_32=category%3Asecurity

if(description)
{
 script_id(11635);
 
 script_version("$Revision: 1.2 $");

 name["english"] = "Java Media Framework (JMF) Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Sun Microsystems's Java Media Framework (JMF).

There is a bug in the version installed which may allow an untrusted
applet to crash the Java Virtual Machine it is being run on, or even
to gain unauthorized privileges.

An attacker could exploit this flaw to execute arbitrary code on
this host. To exploit this flaw, the attacker would need to 
send a rogue java applet to a user of the remote host and have
him execute it (since Java applets are running in a sandbox,
a user may probably feel safe executing it). 


Solution : Upgrade to JMF 2.1.1e or newer
Risk : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of JMF";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

port = kb_smb_transport();
if ( ! get_port_state(port) ) exit(1);

soc = open_sock_tcp(port);
if ( ! soc ) exit(1);

session_init(socket:soc, hostname:kb_smb_name());

r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}

key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\Sun Microsystems, Inc.\JMF", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

item = RegQueryValue(handle:key_h, item:"LatestVersion");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel();

if ( isnull(item) ) exit(1);
if(ereg(pattern:"^([0-1]\.|2\.0|2\.1\.0|2\.1\.1($|[a-d]))$", string:item[1]))security_warning(port);
