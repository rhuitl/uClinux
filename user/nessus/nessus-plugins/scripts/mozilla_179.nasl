#
# (C) Tenable Network Security
#


if (description) {
  script_id(18813);
  script_version("$Revision: 1.4 $");

  script_cve_id(
    "CVE-2005-1937",
    "CVE-2005-2260",
    "CVE-2005-2261",
    "CVE-2005-2263",
    "CVE-2005-2265",
    "CVE-2005-2266",
    "CVE-2005-2268",
    "CVE-2005-2269",
    "CVE-2005-2270"
  );
  script_bugtraq_id(14242);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"7296");
    script_xref(name:"OSVDB", value:"17397");
  }

  name["english"] = "Mozilla Browser < 1.7.9";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

A web browser installed on the remote host contains multiple
vulnerabilities. 

Description :

The remote version of this software contains various security issues,
one of which may allow an attacker to execute arbitrary code on the
remote host. 

See also :

http://www.mozilla.org/security/announce/2005/mfsa2005-45.html
http://www.mozilla.org/security/announce/2005/mfsa2005-46.html
http://www.mozilla.org/security/announce/2005/mfsa2005-48.html
http://www.mozilla.org/security/announce/2005/mfsa2005-50.html
http://www.mozilla.org/security/announce/2005/mfsa2005-51.html
http://www.mozilla.org/security/announce/2005/mfsa2005-52.html
http://www.mozilla.org/security/announce/2005/mfsa2005-54.html
http://www.mozilla.org/security/announce/2005/mfsa2005-55.html
http://www.mozilla.org/security/announce/2005/mfsa2005-56.html

Solution : 

Upgrade to Mozilla 1.7.9 or later.

Risk factor : 

High / CVSS Base Score : 8
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Mozilla < 1.7.9";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Version");

 exit(0);
}


ver = get_kb_item("Mozilla/Version");
if (!ver) exit(0);

ver = split(ver, sep:'.', keep:FALSE);
if (
  int(ver[0]) < 1 ||
  (
    int(ver[0]) == 1 &&
    (
      int(ver[1]) < 7 ||
      (int(ver[1]) == 7 && int(ver[2]) < 9)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
