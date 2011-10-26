#
# (C) Tenable Network Security
#


if (description) {
  script_id(19696);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-2602");
  script_bugtraq_id(14526, 14924);

  name["english"] = "Netscape Browser <= 8.0.3.3";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis : 

A web browser on the remote host is prone to multiple flaws, including
arbitrary code execution.

Description :

The remote host is using Netscape Browser / Netscape Navigator, an
alternative web browser. 

The version of Netscape Browser / Netscape Navigator installed on the
remote host is prone to multiple flaws, including one that may allow
an attacker to execute arbitrary code on the affected system. 

See also : 

http://security-protocols.com/advisory/sp-x17-advisory.txt
http://www.mozilla.org/security/announce/mfsa2005-58.html
http://browser.netscape.com/ns8/security/alerts.jsp

Solution : 

Upgrade to Netscape Browser version 8.0.4 or later.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Netscape Browser <= 8.0.3.3";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
  script_dependencies("netscape_browser_detect.nasl");

  exit(0);
}


ver = get_kb_item("Netscape/Browser/Version");
if (
  ver && 
  ver =~ "^8\.0\.[0-3][^0-9]?)"
) {
  security_hole(0);
}

ver = get_kb_item("Netscape/Navigator/Version");
if (
  ver && 
  ver =~ "^7\.2[^0-9]?"
) {
  security_hole(0);
}

