#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12452);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0991");

 name["english"] = "RHSA-2004-019: mailman";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mailman packages that close a DoS vulnerability present in mailman
  versions prior to version 2.1 are now available.

  Mailman is a mailing list manager.

  Matthew Galgoci of Red Hat discovered a Denial of Service (DoS)
  vulnerability in versions of Mailman prior to 2.1. An attacker could send
  a carefully-crafted message causing mailman to crash. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2003-0991 to this issue.

  Users of Mailman are advised to upgrade to the erratum packages, which
  include a backported security fix and are not vulnerable to this issue.

  Red Hat would like to thank Barry Warsaw for providing a patch for this
  issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-019.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mailman packages";
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
if ( rpm_check( reference:"mailman-2.0.13-5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mailman-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0991", value:TRUE);
}

set_kb_item(name:"RHSA-2004-019", value:TRUE);
