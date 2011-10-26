#
# (C) Tenable Network Security
#


if (description) {
  script_id(21784);
  script_version("$Revision: 1.2 $");
  script_bugtraq_id(18737, 18738, 18739);
  script_cve_id("CVE-2006-3117", "CVE-2006-2198", "CVE-2006-2199");

  script_name(english:"OpenOffice.org < 2.0.3");
  script_summary(english:"Checks for the version of OpenOffice.org");
 
  desc = "
Synopsis :

Arbitrary code can be executed on the remote host through OpenOffice.org

Description :

The remote host is running a version of OpenOffice.org which is older than 
version 2.0.3.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to a user of the 
remote computer and have him open it. The file could be crafted in such a
way that it could exploit a buffer overflow in OpenOffice.org's XML parser,
or by containing rogue macros.


Solution : 

Upgrade to OpenOffice.org 2.0.3 or newer

See also :

http://www.openoffice.org/security/CVE-2006-2198.html
http://www.openoffice.org/security/CVE-2006-2199.html
http://www.openoffice.org/security/CVE-2006-3117.html


Risk factor : 

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);



ver = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{686BB230-DE5B-44F4-8DB0-4F9BEE7310F7}/DisplayVersion");
if ( ! ver ) exit(0);

# OpenOffice 2.0.3 => Build 2.0.9044
vers = split(ver, sep:'.', keep:FALSE);
if ( int(vers[0]) < 2 || (int(vers[0]) == 2 && int(vers[1]) == 0 &&  int(vers[2]) < 9044  ) )
		security_warning(0);

