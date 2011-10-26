#
# (C) Tenable Network Security
#


if (description) {
  script_id(20219);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-2938");
  script_bugtraq_id(15446);

  script_name(english:"iTunes For Windows Local Code Execution Vulnerability (registry check)");
  script_summary(english:"Checks for an local code execution vulnerability in iTunes for Windows");
 
  desc = "
Synopsis :

The remote host contains an application that is affected by a local
code execution flaw. 

Description :

The version of iTunes for Windows on the remote host launches a helper
application by searching for it through various system paths.  An
attacker with local access can leverage this issue to place a
malicious program in a system path and have it called before the
helper application. 

See also :

http://www.idefense.com/application/poi/display?id=340&type=vulnerabilities
http://lists.apple.com/archives/security-announce/2005/Nov/msg00001.html

Solution :

Upgrade to iTunes 6 for Windows or later. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:L/AC:L/Au:NR/C:C/I:C/A:C/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for iTunes.
ver = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{872653C6-5DDC-488B-B7C2-CF9E4D9335E5}\DisplayVersion");
if (ver && ver =~ "^[0-5]\.") security_warning(port);
