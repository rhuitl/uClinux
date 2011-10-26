#
# (C) Tenable Network Security
#


if (description) {
  script_id(19694);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2871");
  script_bugtraq_id(14784);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"19255");

  name["english"] = "Mozilla Thunderbird < 1.0.7";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

The remote version of Mozilla Thunderbird suffers from several flaws. 

Description :

The remote host is using Mozilla Thunderbird, an email client. 

The remote version of this software contains various security issues
which may allow an attacker to execute arbitrary code on the remote
host and to disguise URLs. 

See also : 

http://www.securityfocus.com/archive/1/407704
http://security-protocols.com/advisory/sp-x17-advisory.txt
http://www.mozilla.org/security/idn.html

Solution : 

Upgrade to Thunderbird 1.0.7 when it becomes available or disable IDN
support in the browser following the instructions in the vendor's
advisory. 

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Determines the version of Thunderbird";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}


ver = get_kb_item("Mozilla/Thunderbird/Version");
if (!ver) exit(0);

ver = split(ver, sep:'.', keep:FALSE);
if (
  int(ver[0]) < 1 ||
  (int(ver[0]) == 1 && int(ver[1]) == 0 && int(ver[2]) < 7)
) security_warning(get_kb_item("SMB/transport"));
