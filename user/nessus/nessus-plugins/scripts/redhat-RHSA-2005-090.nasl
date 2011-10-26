#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17182);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0085");

 name["english"] = "RHSA-2005-090: htdig";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated htdig packages that fix a security flaw are now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The ht://Dig system is a Web search and indexing system for a small domain
  or intranet.

  Michael Krax reported a cross-site scripting bug affecting htdig. An
  attacker could construct a carefully crafted URL which can cause a web
  browser to execute malicious script once visited. The Common
  Vulnerabilities and Exposures project has assigned the name CVE-2005-0085
  to this issue.

  Users of htdig should upgrade to these updated packages, which contain a
  backported patch, and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-090.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the htdig packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"htdig-3.2.0b6-3.40.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"htdig-web-3.2.0b6-3.40.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"htdig-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0085", value:TRUE);
}

set_kb_item(name:"RHSA-2005-090", value:TRUE);
