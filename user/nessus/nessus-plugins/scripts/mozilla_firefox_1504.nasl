#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21627);
  script_version("$Revision: 1.5 $");

  script_cve_id(
    "CVE-2006-1942", 
    "CVE-2006-2775", 
    "CVE-2006-2776", 
    "CVE-2006-2777", 
    "CVE-2006-2778", 
    "CVE-2006-2779", 
    "CVE-2006-2780", 
    "CVE-2006-2782", 
    "CVE-2006-2783", 
    "CVE-2006-2784", 
    "CVE-2006-2785", 
    "CVE-2006-2786", 
    "CVE-2006-2787"
  );
  script_bugtraq_id(18228);

  script_name(english:"Firefox < 1.5.0.4");
  script_summary(english:"Checks version of Firefox");

  desc = "
Synopsis :

The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.

Description :

The installed version of Firefox is affected by various security issues,
some of which may lead to execution of arbitrary code on the affected
host subject to the user's privileges. 

See also : 

http://www.mozilla.org/security/announce/2006/mfsa2006-31.html
http://www.mozilla.org/security/announce/2006/mfsa2006-32.html
http://www.mozilla.org/security/announce/2006/mfsa2006-33.html
http://www.mozilla.org/security/announce/2006/mfsa2006-34.html
http://www.mozilla.org/security/announce/2006/mfsa2006-35.html
http://www.mozilla.org/security/announce/2006/mfsa2006-36.html
http://www.mozilla.org/security/announce/2006/mfsa2006-37.html
http://www.mozilla.org/security/announce/2006/mfsa2006-38.html
http://www.mozilla.org/security/announce/2006/mfsa2006-39.html
http://www.mozilla.org/security/announce/2006/mfsa2006-41.html
http://www.mozilla.org/security/announce/2006/mfsa2006-42.html
http://www.mozilla.org/security/announce/2006/mfsa2006-43.html

Solution : 

Upgrade to Firefox 1.5.0.4 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

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
      (int(ver[1]) == 5 && int(ver[2]) == 0 && int(ver[3]) < 4)
    )
  )
) security_warning(get_kb_item("SMB/transport"));
