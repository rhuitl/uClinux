#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20174);
 script_version("$Revision: 1.3 $");
 script_cve_id("CVE-2005-1693");
 script_bugtraq_id(13710);
 name["english"] = "Computer Associates Vet Library Remote Heap Overflow Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote host is running a version of Computer Associates Vet Scan Engine
which is vulnerable to heap overflow. An attacker may exploit this flaw to
execute arbitrary code on the remote host with the privileges of a local 
administrator or to disable the remote service remotely.

To exploit this flaw, an attacker would need to send a specially crafted file
to the remote antivirus library.

Solution :

http://www3.ca.com/securityadvisor/vulninfo/vuln.aspx?id=32896

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of CA Vet Scan Engine";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");


if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if(!get_port_state(port))exit(1);
soc = open_sock_tcp(port);
if(!soc)exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) ) 
{
 NetUseDel();
 exit(1);
}

key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\ComputerAssociates\ScanEngine\Path", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

value = RegQueryValue(handle:key_h, item:"Engine");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
if ( isnull(value) )
{
 NetUseDel();
 exit(0);
}


share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:value[1]);
exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\VetE.dll", string:value[1]);
NetUseDel(close:FALSE);

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) {
 NetUseDel();
 exit(1);
}



handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);


if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if (!isnull(v))
 if ( ( v[0] < 11 ) || 
      ( ( v[0] == 11 ) && ( v[1] < 9 ) ) || 
      ( ( v[0] == 11 ) && ( v[1] == 9 ) && ( v[2] < 1 ) ) )
    security_hole(port);
}

NetUseDel();
