#
#  (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability. 

Description :

The Windows remote host contains the eGatherer ActiveX control, which
is typically installed by default on IBM workstations and laptops and
used for automatically locating drivers and updates on IBM / Lenovo
support sites. 

The version of this ActiveX control on the remote host reportedly
contains a stack-based buffer overflow in the 'RunEgatherer' function. 
Exploitation of this issue may allow an unauthenticated remote
attacker to execute arbitrary code subject to the user's privileges. 

See also :

http://research.eeye.com/html/advisories/published/AD20060816.html
http://lists.grok.org.uk/pipermail/full-disclosure/2006-August/048876.html

Solution :

Upgrade to version 3.20.284.0 or later of the ActiveX control. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(22253);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-4221");
  script_bugtraq_id(19554);

  script_name(english:"IBM eGatherer ActiveX Control RunEgatherer Function Buffer Overflow Vulnerability");
  script_summary(english:"Checks version of IBM eGatherer ActiveX control"); 
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Check whether it's installed.
clid = "74FFE28D-2378-11D5-990C-006094235084";
key = "SOFTWARE\Classes\CLSID\{" + clid +  "}\InprocServer32";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
file = NULL;
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) file = value[1];

  RegCloseKey(handle:key_h);
}


# If it is...
if (file)
{
  # Determine the version from the DLL itself.
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:file);
  dll =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:file);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # Check the version number.
  if (
    !isnull(ver) &&
    (
      ver[0] < 3 ||
      (
        ver[0] == 3 &&
        (
          ver[1] < 20 ||
          (ver[1] == 20 && ver[2] < 284)
        )
      )
    )
  )
  {
    version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

    report = desc + string(
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Version ", version, " of the control is installed as \n",
      "\n",
      "  ", file, "\n"
    );
    security_warning(port:port, data:report);
  }
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
