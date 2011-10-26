#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12337);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0461", "CVE-2002-1319");

 name["english"] = "RHSA-2002-263: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  The kernel in Red Hat Linux Advanced Server 2.1 is vulnerable to a local
  denial of service attack. Updated packages are available which address this
  vulnerability.

  [Updated 28 August 2003]
  Added CVE-2003-0461 to the list of security issues that were fixed by this
  advisory (there are no changes to the packages themselves).

  The Linux kernel handles the basic functions of the operating system.
  A vulnerability in the Linux kernel has been discovered in which a non-root
  user can cause the machine to freeze. This kernel addresses the
  vulnerability.

  Note: This bug is specific to the x86 architecture kernels only, and does
  not affect ia64 or other architectures.

  In addition, /proc/tty/driver/serial reveals the exact number of
  characters used in serial links, which could allow local users to obtain
  potentially sensitive information such as password lengths.

  All users should upgrade to these errata packages, which are not vulnerable
  to these issues.

  Thanks go to Christopher Devine for reporting the vulnerability on Bugtraq,
  and Petr Vandrovec for being the first to supply a fix to the community.




Solution : http://rhn.redhat.com/errata/RHSA-2002-263.html
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
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0461", value:TRUE);
 set_kb_item(name:"CVE-2002-1319", value:TRUE);
}

set_kb_item(name:"RHSA-2002-263", value:TRUE);
