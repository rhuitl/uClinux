#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21226);
  script_version("$Revision: 1.2 $");

  script_cve_id(
    "CVE-2006-0748",
    "CVE-2006-1529", 
    "CVE-2006-1530", 
    "CVE-2006-1531", 
    "CVE-2006-1723", 
    "CVE-2006-1724",
    "CVE-2006-1725", 
    "CVE-2006-1726", 
    "CVE-2006-1727", 
    "CVE-2006-1728", 
    "CVE-2006-1729", 
    "CVE-2006-1730"
  );
  script_bugtraq_id(17516);

  script_name(english:"SeaMonkey < 1.0.1");
  script_summary(english:"Checks version of SeaMonkey");

  desc = "
Synopsis :

A web browser on the remote host is prone to multiple flaws. 

Description :

The remote Windows host is using SeaMonkey, an alternative web browser
and application suite. 

The installed version of SeaMonkey contains various security issues,
some of which may lead to execution of arbitrary code on the affected
host subject to the user's privileges. 

See also :

http://www.mozilla.org/security/announce/2006/mfsa2006-20.html
http://www.mozilla.org/security/announce/2006/mfsa2006-22.html
http://www.mozilla.org/security/announce/2006/mfsa2006-23.html
http://www.mozilla.org/security/announce/2006/mfsa2006-24.html
http://www.mozilla.org/security/announce/2006/mfsa2006-25.html
http://www.mozilla.org/security/announce/2006/mfsa2006-26.html
http://www.mozilla.org/security/announce/2006/mfsa2006-28.html
http://www.mozilla.org/security/announce/2006/mfsa2006-29.html

Solution : 

Upgrade to SeaMonkey 1.0.1 or later. 

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


ver = get_kb_item("SeaMonkey/Version");
if (!ver) exit(0);

ver = split(ver, sep:'.', keep:FALSE);
if (
  int(ver[0]) < 1 ||
  (int(ver[0]) == 1 && int(ver[1]) == 0 && int(ver[3]) < 1)
) security_hole(get_kb_item("SMB/transport"));
