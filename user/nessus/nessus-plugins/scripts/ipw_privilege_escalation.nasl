#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22132);
 script_version("$Revision: 1.1 $");
 script_bugtraq_id(19299);
 name["english"] = "Intel PRO/Wireless 2100 Network Connection Driver Local Privilege Escalation Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A local user can elevate his privileges on the remote host.

Description :

The remote host is running a version of Intel Wireless/PRO 2100 driver
which is vulnerable to certain malformed frames. A local attacker may
exploit this flaw to elevate his privileges (SYSTEM) on the remote host.

To exploit this flaw, an attacker would need to send a specially crafted
wireless frame to the intel driver.

Solution :

http://support.intel.com/support/wireless/wlan/pro2100/sb/CS-023067.htm

Risk factor :

High / CVSS Base Score : 7 
(AV:L/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Intel Wireless/PRO 2100 driver";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


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

key_h = RegOpenKey(handle:hklm, key:"SYSTEM\CurrentControlSet\Services\w70n51", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

value = RegQueryValue(handle:key_h, item:"ImagePath");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
if ( isnull(value) )
{
 NetUseDel();
 exit(0);
}

value = hotfix_get_systemroot() + "\" + value[1];
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:value);
exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:value);
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
 if ( ( v[0] < 1 ) || 
      ( ( v[0] == 1 ) && ( v[1] < 2 ) ) || 
      ( ( v[0] == 1 ) && ( v[1] == 2 ) && ( v[2] < 4 ) ) ||
      ( ( v[0] == 1 ) && ( v[1] == 2 ) && ( v[2] == 4 ) && ( v[3] < 37 ) ) )
    security_hole(port);
}

NetUseDel();
