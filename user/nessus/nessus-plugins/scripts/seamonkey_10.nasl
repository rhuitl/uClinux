#
# (C) Tenable Network Security
#


if (description) {
  script_id(20863);
  script_version("$Revision: 1.3 $");

  script_cve_id(
    "CVE-2006-0294",
    "CVE-2006-0295",
    "CVE-2006-0297",
    "CVE-2006-0298",
    "CVE-2006-0299",
    "CVE-2006-0749",
    "CVE-2006-1731",
    "CVE-2006-1732",
    "CVE-2006-1733",
    "CVE-2006-1734",
    "CVE-2006-1735",
    "CVE-2006-1736",
    "CVE-2006-1739",
    "CVE-2006-1740",
    "CVE-2006-1741",
    "CVE-2006-1742"
  );
  script_bugtraq_id(16476);

  script_name(english:"SeaMonkey < 1.0");
  script_summary(english:"Checks for SeaMonkey < 1.0");

  desc = "
Synopsis :

A web browser on the remote host is prone to multiple flaws. 

Description :

The remote Windows host is using SeaMonkey, an alternative web browser
and application suite. 

The installed version of SeaMonkey contains various security issues,
some of which can be exploited to execute arbitrary code on the
affected host subject to the user's privileges. 

See also :

http://www.mozilla.org/security/announce/2006/mfsa2006-01.html
http://www.mozilla.org/security/announce/2006/mfsa2006-02.html
http://www.mozilla.org/security/announce/2006/mfsa2006-03.html
http://www.mozilla.org/security/announce/2006/mfsa2006-04.html
http://www.mozilla.org/security/announce/2006/mfsa2006-06.html
http://www.mozilla.org/security/announce/2006/mfsa2006-07.html
http://www.mozilla.org/security/announce/2006/mfsa2006-08.html
http://www.mozilla.org/security/announce/2006/mfsa2006-09.html
http://www.mozilla.org/security/announce/2006/mfsa2006-10.html
http://www.mozilla.org/security/announce/2006/mfsa2006-11.html
http://www.mozilla.org/security/announce/2006/mfsa2006-12.html
http://www.mozilla.org/security/announce/2006/mfsa2006-13.html
http://www.mozilla.org/security/announce/2006/mfsa2006-14.html
http://www.mozilla.org/security/announce/2006/mfsa2006-15.html
http://www.mozilla.org/security/announce/2006/mfsa2006-16.html
http://www.mozilla.org/security/announce/2006/mfsa2006-17.html
http://www.mozilla.org/security/announce/2006/mfsa2006-18.html
http://www.mozilla.org/security/announce/2006/mfsa2006-19.html

Solution : 

Upgrade to SeaMonkey 1.0 or later.

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
if (ver && ver =~ "^(0\.|1\.0[ab])")
  security_hole(get_kb_item("SMB/transport"));
