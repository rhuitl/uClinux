#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12494);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0461", "CVE-2003-0465", "CVE-2003-0984", "CVE-2003-1040", "CVE-2004-0003", "CVE-2004-0010");

 name["english"] = "RHSA-2004-188: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages are now available as part of ongoing
  support and maintenance of Red Hat Enterprise Linux version
  3. This is the second regular update.

  The Linux kernel handles the basic functions of the
  operating system.


  A minor flaw was found where /proc/tty/driver/serial reveals
  the exact character counts for serial links. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2003-0461 to this issue.

  The kernel strncpy() function in Linux 2.4 and 2.5 does not
  pad the target buffer with null bytes on architectures other
  than x86, as opposed to the expected libc behavior, which
  could lead to information leaks. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name
  CVE-2003-0465 to this issue.

  A minor data leak was found in two real time clock drivers
  (for /dev/rtc). The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name
  CVE-2003-0984 to this issue.

  A flaw in the R128 Direct Render Infrastructure (dri) driver
  could allow local privilege escalation. This driver is part
  of the kernel-unsupported package. The Common Vulnera-
  bilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2004-0003 to this issue.

  A flaw in ncp_lookup() in ncpfs could allow local privilege
  escalation. The ncpfs module allows a system to mount
  volumes of NetWare servers or print to NetWare printers and
  is in the kernel-unsupported package. The Common Vulnera-
  bilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2004-0010 to this issue.

  (Note that the kernel-unsupported package contains drivers
  and other modules that are unsupported and therefore might
  contain security problems that have not been addressed.)

  All Red Hat Enterprise Linux 3 users are advised to upgrade
  their kernels to the packages associated with their machine
  architectures and configurations as listed in this erratum.




Solution : http://rhn.redhat.com/errata/RHSA-2004-188.html
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
if ( rpm_check( reference:"kernel-BOOT-2.4.21-15.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-15.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-15.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-0461", value:TRUE);
 set_kb_item(name:"CVE-2003-0465", value:TRUE);
 set_kb_item(name:"CVE-2003-0984", value:TRUE);
 set_kb_item(name:"CVE-2003-1040", value:TRUE);
 set_kb_item(name:"CVE-2004-0003", value:TRUE);
 set_kb_item(name:"CVE-2004-0010", value:TRUE);
}

set_kb_item(name:"RHSA-2004-188", value:TRUE);
