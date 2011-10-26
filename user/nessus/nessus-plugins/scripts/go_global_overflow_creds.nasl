#
# (C) Tenable Network Security
#


if (description) {
  script_id(20179);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-3483");
  script_bugtraq_id(15285);

  script_name(english:"GO-Global Buffer Overflow Vulnerability (registry check)");
  script_summary(english:"Checks for buffer overflow vulnerability in GO-Global");
 
  desc = "
Synopsis :

The remote display client or server is affected by a buffer overflow
vulnerability. 

Description :

According to the Windows registry, the remote host is running a
version of the GO-Global remote display client or server that fills a
small buffer with user-supplied data without first checking its size. 
An attacker can leverage this issue to overflow the buffer, causing
the server to crash and possibly even allowing for arbitrary code
execution on the remote host. 

See also : 

http://lists.grok.org.uk/pipermail/full-disclosure/2005-November/038371.html

Solution : 

Upgrade to GO-Global version 3.1.0.3281 or later.

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

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

key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\GraphOn\Bridges", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

value = RegQueryValue(handle:key_h, item:"RootPath");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
if ( isnull(value) )
{
 NetUseDel();
 exit(0);
}


share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:value[1]);
exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Programs\cs.dll", string:value[1]);
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
 if ( ( v[0] < 3 ) || 
      ( ( v[0] == 3 ) && ( v[1] < 1 ) ) || 
      ( ( v[0] == 3 ) && ( v[1] == 1 ) && ( v[2] == 0 ) && ( v[3] < 3281 ) ) )
    security_hole(port);
}

NetUseDel();
