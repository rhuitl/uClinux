#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14696);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0500", "CVE-2004-0754", "CVE-2004-0784", "CVE-2004-0785");

 name["english"] = "RHSA-2004-400: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated gaim package that fixes several security issues is now
  available.

  Gaim is an instant messenger client that can handle multiple protocols.

  Buffer overflow bugs were found in the Gaim MSN protocol handler. In order
  to exploit these bugs, an attacker would have to perform a man in the
  middle attack between the MSN server and the vulnerable Gaim client. Such
  an attack could allow arbitrary code execution. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CVE-2004-0500
  to this issue.

  Buffer overflow bugs have been found in the Gaim URL decoder, local
  hostname resolver, and the RTF message parser. It is possible that a
  remote attacker could send carefully crafted data to a vulnerable client
  and lead to a crash or arbitrary code execution. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0785 to this issue.

  A shell escape bug has been found in the Gaim smiley theme file
  installation. When a user installs a smiley theme, which is contained
  within a tar file, the unarchiving of the data is done in an unsafe manner.
  An attacker could create a malicious smiley theme that would execute
  arbitrary commands if the theme was installed by the victim. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0784 to this issue.

  An integer overflow bug has been found in the Gaim Groupware message
  receiver. It is possible that if a user connects to a malicious server,
  an attacker could send carefully crafted data which could lead to arbitrary
  code execution on the victims machine. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2004-0754 to
  this issue.

  Users of Gaim are advised to upgrade to this updated package which
  contains Gaim version 0.82 and is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-400.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gaim packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gaim-0.82.1-0.RHEL3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gaim-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0500", value:TRUE);
 set_kb_item(name:"CVE-2004-0754", value:TRUE);
 set_kb_item(name:"CVE-2004-0784", value:TRUE);
 set_kb_item(name:"CVE-2004-0785", value:TRUE);
}

set_kb_item(name:"RHSA-2004-400", value:TRUE);
