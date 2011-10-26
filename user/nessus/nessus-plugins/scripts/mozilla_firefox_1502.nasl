#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21225);
  script_version("$Revision: 1.5 $");

  script_cve_id(
    "CVE-2006-0292",
    "CVE-2006-0293",
    "CVE-2006-1529",
    "CVE-2006-1530",
    "CVE-2006-1531",
    "CVE-2006-1723",
    "CVE-2006-1725",
    "CVE-2006-1726",
    "CVE-2006-1727",
    "CVE-2006-1728",
    "CVE-2006-1729",
    "CVE-2006-1730"
  );
  script_bugtraq_id(17499, 17516);

  script_name(english:"Firefox < 1.0.8 / 1.5.0.2");
  script_summary(english:"Checks Firefox version number");

  desc = "
Synopsis :

A web browser on the remote host is prone to multiple flaws. 

Description :

The remote Windows host is using Firefox, an alternative web browser. 

The installed version of Firefox contains various security issues,
some of which may lead to execution of arbitrary code on the affected
host subject to the user's privileges. 

See also : 

http://www.mozilla.org/security/announce/2006/mfsa2006-20.html
http://www.mozilla.org/security/announce/2006/mfsa2006-22.html
http://www.mozilla.org/security/announce/2006/mfsa2006-23.html
http://www.mozilla.org/security/announce/2006/mfsa2006-24.html
http://www.mozilla.org/security/announce/2006/mfsa2006-25.html
http://www.mozilla.org/security/announce/2006/mfsa2006-28.html
http://www.mozilla.org/security/announce/2006/mfsa2006-29.html

Solution : 

Upgrade to Firefox 1.0.8 / 1.5.0.2 or later. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 
  script_dependencies("mozilla_org_installed.nasl");

  exit(0);
}


ver = get_kb_item("Mozilla/Firefox/Version");
if (!ver) exit(0);
ver = split(ver, sep:'.', keep:FALSE);
if (
  int(ver[0]) < 1 ||
  (
    int(ver[0]) == 1 &&
    (
      int(ver[1]) < 5 ||
      (int(ver[1]) == 5 && int(ver[2]) == 0 && int(ver[3]) < 2)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
