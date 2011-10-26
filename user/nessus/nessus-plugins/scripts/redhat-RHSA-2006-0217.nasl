#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20966);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0709");

 name["english"] = "RHSA-2006-0217: metamail";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated metamail package that fixes a buffer overflow vulnerability for
  Red Hat Enterprise Linux 2.1 is now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Metamail is a system for handling multimedia mail.

  A buffer overflow bug was found in the way Metamail processes certain mail
  messages. An attacker could create a carefully-crafted message such that
  when it is opened by a victim and parsed through Metamail, it runs
  arbitrary code as the victim. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) assigned the name CVE-2006-0709 to this issue.

  Users of Metamail should upgrade to this updated package, which contains a
  backported patch that is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0217.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the metamail packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"metamail-2.7-30", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"metamail-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-0709", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0217", value:TRUE);
