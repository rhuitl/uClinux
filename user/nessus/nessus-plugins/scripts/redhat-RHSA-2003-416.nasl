#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12443);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0985");

 name["english"] = "RHSA-2003-416: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages are now available that fix a security
  vulnerability which may allow local users to gain root privileges.

  The Linux kernel handles the basic functions of the operating system.

  Paul Starzetz discovered a flaw in bounds checking in mremap() in the Linux
  kernel versions 2.4.23 and previous which may allow a local attacker to
  gain root privileges. No exploit is currently available; however, it is
  believed that this issue is exploitable (although not trivially.) The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2003-0985 to this issue.

  All users of Red Hat Enterprise Linux 3 are advised to upgrade to these
  errata packages, which contain a backported security patch that corrects
  this issue.

  Red Hat would like to thank Paul Starzetz from ISEC for disclosing this
  issue as well as Andrea Arcangeli and Solar Designer for working on the patch.




Solution : http://rhn.redhat.com/errata/RHSA-2003-416.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel packages";
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
if ( rpm_check( reference:"kernel-BOOT-2.4.21-4.0.2.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-4.0.2.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-4.0.2.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-0985", value:TRUE);
}

set_kb_item(name:"RHSA-2003-416", value:TRUE);
