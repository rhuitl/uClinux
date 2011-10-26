#
# (C) Tenable Network Security
#


 desc = "
The remote version of Windows contains a version of the Java JRE
which is older than 1.4.2_06 / 1.3.1_13. 

Even if a newer version of this software is installed, a malicious Java
Applet may invoke a particular version of the Java JRE to be executed with.

As a result, a rogue java applet may exploit this vulnerability to request
to be executed with a known to be buggy version of the Java JRE.


Solution : De-install older versions of the Java JRE
Risk factor: High";

if(description)
{
 script_id(15926);
 script_bugtraq_id(11757);
 script_version("$Revision: 1.4 $");

 name["english"] = " Sun Java Applet Invocation Version Specification";
 script_name(english:name["english"]);


 script_description(english:desc);
 summary["english"] = "Checks for older versions of the Java SDK and JRE";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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

key = "SOFTWARE\JavaSoft\Java Runtime Environment";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}


item= "CurrentVersion";
value = RegQueryValue(handle:key_h, item:item);
if (isnull(value) ) 
{
 RegCloseKey(handle:key_h);
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(1);
}


info = RegQueryInfoKey(handle:key_h);
for ( i = 0 ; i < info[1] ; i ++ )
{
 entries[i] = RegEnumKey(handle:key_h, index:i);
}

RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel();


versions = NULL;
report = desc + '\n\nThe remote host has the following versions installed : \n';
foreach entry (entries)
{
 report += '\n - ' + entry;
 versions += entry + '\n';
}

set_kb_item(name:"SMB/Java/JRE/Version", value:versions);

foreach entry (entries)
{
 if ( ereg(pattern:"^(0\.|1\.[0-2]\.|1\.3\.0|1\.3\.1_([0-9]$|1[0-2]$)|1\.4\.([01]|2_0[0-5]))", string:entry) ) 
	{
	 security_hole ( port:port, data:report );
	 exit(0);
	}
}
