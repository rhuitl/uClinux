#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12468);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0077");

 name["english"] = "RHSA-2004-066: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that fix a security vulnerability that may allow
  local users to gain root privileges are now available. These packages also
  resolve other minor issues.

  The Linux kernel handles the basic functions of the operating
  system.

  Paul Starzetz discovered a flaw in return value checking in mremap() in the
  Linux kernel versions 2.4.24 and previous that may allow a local attacker
  to gain root privileges. No exploit is currently available; however this
  issue is exploitable. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0077 to this issue.

  All users are advised to upgrade to these errata packages, which contain
  backported security patches that correct these issues.

  Red Hat would like to thank Paul Starzetz from ISEC for reporting this issue.

  For the IBM S/390 and IBM eServer zSeries architectures, the upstream
  version of the s390utils package (which fixes a bug in the zipl
  bootloader) is also included.




Solution : http://rhn.redhat.com/errata/RHSA-2004-066.html
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
if ( rpm_check( reference:"kernel-BOOT-2.4.21-9.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-9.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-9.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0077", value:TRUE);
}

set_kb_item(name:"RHSA-2004-066", value:TRUE);
