#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12458);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0700", "CVE-2004-0003", "CVE-2002-1574");

 name["english"] = "RHSA-2004-044: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages are now available that fix a few security issues,
  an NFS performance issue, and an e1000 driver loading issue introduced in
  Update 3.

  The Linux kernel handles the basic functions of the operating system.

  Alan Cox found issues in the R128 Direct Render Infrastructure that
  could allow local privilege escalation. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2004-0003 to
  this issue.

  The C-Media PCI sound driver in Linux before 2.4.22 does not use the
  get_user function to access userspace in certain conditions, which crosses
  security boundaries. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2003-0700 to this issue.

  An overflow was found in the ixj telephony card driver in Linux kernels
  prior to 2.4.20. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2002-1574 to this issue.

  All users are advised to upgrade to these errata packages, which contain
  backported security patches that corrects these issues. These packages
  also contain a fix to enhance NFS performance, which was degraded in the
  last kernel update as part of Update 3.




Solution : http://rhn.redhat.com/errata/RHSA-2004-044.html
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
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.37", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.37", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.37", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.37", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0700", value:TRUE);
 set_kb_item(name:"CVE-2004-0003", value:TRUE);
 set_kb_item(name:"CVE-2002-1574", value:TRUE);
}

set_kb_item(name:"RHSA-2004-044", value:TRUE);
