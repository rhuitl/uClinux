#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(20729);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-4459");
  script_bugtraq_id(15998);
  name["english"] = "VMWare Remote Arbitrary Code Execution Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

It is possible to execute code on the remote system.

Description :

According to its version number, the VMware program on the remote host
may allow an attacker to execute code on the system hosting the VMware
instance.

The vulnerability can be exploited by sending specially crafted FTP PORT
and EPRT requests.

To be exploitable, the VMware system must be configured to use NAT networking.

See also :

http://www.vmware.com/support/kb/enduser/std_adp.php?p_faqid=2000

Solution :

Upgrade to :

- VMware Workstation 5.5.1 or higher
- VMware Workstation 4.5.2 or higher
- VMware Player 1.0.1 or higher
- VMware GSX Server 3.2.1 or higher

Risk factor :

High / CVSS Base Score : 9.9
(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)";

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for VMware version";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# VMware Workstation

key1 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{98D1A713-438C-4A23-8AB6-41B37C4A2D47}/DisplayName";
key2 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{98D1A713-438C-4A23-8AB6-41B37C4A2D47}/DisplayVersion";

name = get_kb_item (key1);
version = get_kb_item (key2);

if (!isnull (name) && (name == "VMware Workstation") )
{
 version = split (version, sep:".", keep:FALSE);

 version[0] = int(version[0]);
 version[1] = int(version[1]);
 version[2] = int(version[2]);

 if ( (version[0] < 4) ||
      ( (version[0] == 4) && (version[1] < 5) ) ||
      ( (version[0] == 4) && (version[1] == 5) && (version[2] < 3) ) ||
      ( (version[0] == 5) && (version[1] < 5) ) ||
      ( (version[0] == 5) && (version[1] == 5) && (version[2] < 1) ) )
 {
  security_hole (port);
  exit (0);
 }
}


# VMware GSX Server

key1 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{5B9605EF-01FA-4429-8174-5A1039B0A7A5}/DisplayName";
key2 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{5B9605EF-01FA-4429-8174-5A1039B0A7A5}/DisplayVersion";

name = get_kb_item (key1);
version = get_kb_item (key2);

if (!isnull (name) && (name >< "VMware GSX Server") )
{
 version = split (version, sep:".", keep:FALSE);

 version[0] = int(version[0]);
 version[1] = int(version[1]);
 version[2] = int(version[2]);

 if ( (version[0] < 3) ||
      ( (version[0] == 3) && (version[1] < 2) ) ||
      ( (version[0] == 3) && (version[1] == 2) && (version[2] < 1) ) )
 {
  security_hole (port);
  exit (0);
 }
}


# VMware Player

key1 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{31799B14-B3E7-4522-B393-6206C03EC5D3}/DisplayName";
key2 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{31799B14-B3E7-4522-B393-6206C03EC5D3}/DisplayVersion";

name = get_kb_item (key1);
version = get_kb_item (key2);

if (!isnull (name) && (name >< "VMware Player") )
{
 version = split (version, sep:".", keep:FALSE);

 version[0] = int(version[0]);
 version[1] = int(version[1]);
 version[2] = int(version[2]);

 if ( (version[0] < 1) ||
      ( (version[0] == 1) && (version[1] == 0) && (version[2] < 1) ) )
 {
  security_hole (kb_smb_transport());
  exit (0);
 }
}
