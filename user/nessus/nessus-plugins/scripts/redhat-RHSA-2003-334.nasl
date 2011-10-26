#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12434);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0859");

 name["english"] = "RHSA-2003-334: glibc";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated glibc packages that resolve a vulnerability and address several
  bugs
  are now available.

  The glibc packages contain GNU libc, which provides standard system
  libraries.

  Herbert Xu reported that various applications can accept spoofed messages
  sent on the kernel netlink interface by other users on the local machine.
  This could lead to a local denial of service attack. The glibc function
  getifaddrs uses netlink and could therefore be vulnerable to this issue.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2003-0859 to this issue.

  In addition to the security issues, a number of other bugs were fixed.

  Users are advised to upgrade to these erratum packages, which contain a
  patch that checks that netlink messages actually came from the kernel
  and patches for the various bug fixes.




Solution : http://rhn.redhat.com/errata/RHSA-2003-334.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the glibc packages";
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
if ( rpm_check( reference:"glibc-2.3.2-95.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-common-2.3.2-95.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.3.2-95.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-headers-2.3.2-95.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.3.2-95.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-utils-2.3.2-95.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nscd-2.3.2-95.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.3.2-95.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"glibc-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-0859", value:TRUE);
}

set_kb_item(name:"RHSA-2003-334", value:TRUE);
