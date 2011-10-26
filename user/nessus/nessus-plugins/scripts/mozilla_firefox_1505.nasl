#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22095);
  script_version("$Revision: 1.5 $");

  script_cve_id(
    "CVE-2006-3113",
    "CVE-2006-3677",
    "CVE-2006-3801",
    "CVE-2006-3802",
    "CVE-2006-3803",
    "CVE-2006-3805",
    "CVE-2006-3806",
    "CVE-2006-3807",
    "CVE-2006-3808",
    "CVE-2006-3809",
    "CVE-2006-3810",
    "CVE-2006-3811",
    "CVE-2006-3812"
  );
  script_bugtraq_id(19181, 19192, 19197);

  script_name(english:"Firefox < 1.5.0.5");
  script_summary(english:"Checks version of Firefox");

  desc = "
Synopsis :

The remote Windows host contains a web browser that is affected by
multiple vulnerabilities. 

Description :

The installed version of Firefox is affected by various security
issues, some of which may lead to execution of arbitrary code on the
affected host subject to the user's privileges. 

See also : 

http://www.mozilla.org/security/announce/2006/mfsa2006-44.html
http://www.mozilla.org/security/announce/2006/mfsa2006-45.html
http://www.mozilla.org/security/announce/2006/mfsa2006-46.html
http://www.mozilla.org/security/announce/2006/mfsa2006-47.html
http://www.mozilla.org/security/announce/2006/mfsa2006-48.html
http://www.mozilla.org/security/announce/2006/mfsa2006-50.html
http://www.mozilla.org/security/announce/2006/mfsa2006-51.html
http://www.mozilla.org/security/announce/2006/mfsa2006-52.html
http://www.mozilla.org/security/announce/2006/mfsa2006-53.html
http://www.mozilla.org/security/announce/2006/mfsa2006-54.html
http://www.mozilla.org/security/announce/2006/mfsa2006-55.html
http://www.mozilla.org/security/announce/2006/mfsa2006-56.html

Solution : 

Upgrade to Firefox 1.5.0.5 or later. 

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
      (int(ver[1]) == 5 && int(ver[2]) == 0 && int(ver[3]) < 5)
    )
  )
) security_warning(get_kb_item("SMB/transport"));
