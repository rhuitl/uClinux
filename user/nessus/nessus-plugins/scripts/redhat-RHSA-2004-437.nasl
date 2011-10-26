#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14309);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0178");

 name["english"] = "RHSA-2004-437: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages are now available as part of ongoing
  support and maintenance of Red Hat Enterprise Linux version
  2.1. This is the fifth regular update.

  The Linux kernel handles the basic functions of the operating
  system.

  This is the fifth regular kernel update to Red Hat Enterprise Linux version
  2.1. It contains one minor security fix, many bug fixes, and updates a
  number of device drivers.

  A bug in the SoundBlaster 16 code which did not properly handle certain
  sample sizes has been fixed. This flaw could be used by local users to
  crash a system. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0178 to this issue.

  The following drivers have also been updated:

  * cciss v2.4.52
  * e1000 v5252k1
  * e100 v2.3.43-k1
  * fusion v2.05.16
  * ips v7.00.15
  * aacraid v1.1.5
  * megaraid2 v2.10.6

  All Red Hat Enterprise Linux 2.1 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum.




Solution : http://rhn.redhat.com/errata/RHSA-2004-437.html
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
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.49", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.49", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.49", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.49", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0178", value:TRUE);
}

set_kb_item(name:"RHSA-2004-437", value:TRUE);
