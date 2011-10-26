#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12461);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0078");

 name["english"] = "RHSA-2004-050: mutt";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  New mutt packages that fix a remotely-triggerable crash in the menu drawing
  code are now available.

  Mutt is a text-mode mail user agent.

  A bug was found in the index menu code in versions of mutt. A remote
  attacker could send a carefully crafted mail message that can cause mutt
  to segfault and possibly execute arbitrary code as the victim. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0078 to this issue.

  It is recommended that all mutt users upgrade to these updated packages,
  which contain a backported security patch and are not vulnerable to this
  issue.

  Red Hat would like to thank Niels Heinen for reporting this issue.

  Note: mutt-1.2.5.1 in Red Hat Enterprise Linux 2.1 is not vulnerable to
  this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-050.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mutt packages";
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
if ( rpm_check( reference:"mutt-1.4.1-3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mutt-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0078", value:TRUE);
}

set_kb_item(name:"RHSA-2004-050", value:TRUE);
