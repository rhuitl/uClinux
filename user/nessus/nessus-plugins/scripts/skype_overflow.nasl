#
# (C) Tenable Network Security
#


if (description)
{
 script_id(20090);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2005-3265", "CVE-2005-3267");
 script_bugtraq_id(15190, 15192);
 script_xref(name:"OSVDB", value:"20306");

 name["english"] = "Skype Networking Routine Heap Overflow Vulnerability (SMB check)";
 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote host is running Skype, a peer-to-peer voice over IP
software. 

The remote version of this software is vulnerable to a Heap overflow
in the handling of its data structures.  An attacker can exploit this
flaw by sending a specially crafted network packet to UDP or TCP ports
Skype is listenning on. 

A successful exploitation of this flaw will result in code execution
on the remote host. 

See also : 

http://www.skype.com/security/skype-sb-2005-03.html

Solution :

Upgrade to skype version 1.4.0.84 or later.

Risk factor :

High / CVSS Base Score : 8
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Skype Heap overflow for Windows";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);

 exit(0);
}


include("smb_func.inc");

name = kb_smb_name();
port = kb_smb_transport();
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();

if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

session_init(socket:soc, hostname:name);

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (r != 1)
  exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1);
}


key = "SOFTWARE\Skype\Phone";
item = "SkypePath";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:item);
  if (!isnull(value))
    dir = value[1];

  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (dir)
{
 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dir);
 
 r = NetUseAdd(share:share);
 if (r == 1) 
 {
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dir);
  handle = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  ver = GetFileVersion(handle:handle);

  if (!isnull(ver))
  {
    if ( (ver[0] < 1) ||
         (ver[0] == 1 && ver[1] < 4) ||
         (ver[0] == 1 && ver[1] == 4 && ver[2] == 0 && ver[3] < 84) )
      security_hole(0);
  }
 }
}

NetUseDel();
