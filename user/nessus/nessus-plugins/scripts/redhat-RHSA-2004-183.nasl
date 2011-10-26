#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12493);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0109", "CVE-2004-0424");

 name["english"] = "RHSA-2004-183: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that fix two privilege escalation vulnerabilities
  are now available.

  The Linux kernel handles the basic functions of the operating system.

  iSEC Security Research discovered a flaw in the ip_setsockopt() function
  code of the Linux kernel versions 2.4.22 to 2.4.25 inclusive. This flaw
  also affects the 2.4.21 kernel in Red Hat Enterprise Linux 3 which
  contained a backported version of the affected code. A local user could
  use this flaw to gain root privileges. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2004-0424 to
  this issue.

  iDefense reported a buffer overflow flaw in the ISO9660 filesystem code.
  An attacker could create a malicious filesystem in such a way that root
  privileges may be obtained if the filesystem is mounted. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0109 to this issue.

  All Red Hat Enterprise Linux 3 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum.




Solution : http://rhn.redhat.com/errata/RHSA-2004-183.html
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
if ( rpm_check( reference:"kernel-BOOT-2.4.21-9.0.3.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-9.0.3.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-9.0.3.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0109", value:TRUE);
 set_kb_item(name:"CVE-2004-0424", value:TRUE);
}

set_kb_item(name:"RHSA-2004-183", value:TRUE);
