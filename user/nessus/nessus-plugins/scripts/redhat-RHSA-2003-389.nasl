#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12438);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0961");

 name["english"] = "RHSA-2003-389: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages are now available that fix a security
  vulnerability allowing local users to gain root privileges.

  The Linux kernel handles the basic functions of the operating system.

  A flaw in bounds checking in the do_brk() function in the Linux kernel
  versions 2.4.22 and previous can allow a local attacker to gain root
  privileges. This issue is known to be exploitable; an exploit has been
  seen in the wild that takes advantage of this vulnerability. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2003-0961 to this issue.

  All users of Red Hat Enterprise Linux 2.1 are advised to upgrade to these
  errata packages, which contain a backported security patch that corrects
  this vulnerability.

  Users of Red Hat Enterprise Linux 3 should upgrade to the kernel packages
  provided by RHBA-2003:308 (released on 30 October 2003), which already
  contained a patch correcting this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-389.html
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
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.30", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.30", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.30", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.30", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0961", value:TRUE);
}

set_kb_item(name:"RHSA-2003-389", value:TRUE);
