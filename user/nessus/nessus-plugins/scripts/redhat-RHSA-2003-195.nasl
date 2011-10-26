#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12401);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0247", "CVE-2003-0248", "CVE-2003-0364");

 name["english"] = "RHSA-2003-195: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages for Red Hat Enterprise Linux are now available
  which address several security vulnerabilities.

  The Linux kernel handles the basic functions of the operating system.

  Several security issues have been found that affect the Linux kernel:

  Al Viro found a security issue in the tty layer whereby any user could
  cause a kernel oops. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2003-0247 to this issue.

  Andrea Arcangeli found an issue in the low-level mxcsr code in which a
  malformed address would leave garbage in cpu state registers. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
  name CVE-2003-0248 to this issue.

  The TCP/IP fragment reassembly handling allows remote attackers to cause a
  denial of service (CPU consumption) via packets that cause a large number
  of hash table collisions, a vulnerability similar to CVE-2003-0244. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2003-0364 to this issue.

  These kernels also contain updated fixes for the ioperm security issue, as
  well as fixes for a number of bugs.

  It is recommended that users upgrade to these erratum kernels, which
  contain patches to correct these vulnerabilities.




Solution : http://rhn.redhat.com/errata/RHSA-2003-195.html
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
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.25", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.25", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.25", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.25", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0247", value:TRUE);
 set_kb_item(name:"CVE-2003-0248", value:TRUE);
 set_kb_item(name:"CVE-2003-0364", value:TRUE);
}

set_kb_item(name:"RHSA-2003-195", value:TRUE);
