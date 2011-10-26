#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22015);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2006-2451");

 name["english"] = "RHSA-2006-0574:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that fix a privilege escalation security issue in
  the Red Hat Enterprise Linux 4 kernel are now available.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  During security research, Red Hat discovered a behavioral flaw in core dump
  handling. A local user could create a program that would cause a core file
  to be dumped into a directory they would not normally have permissions to
  write to. This could lead to a denial of service (disk consumption), or
  allow the local user to gain root privileges. (CVE-2006-2451)

  Prior to applying this update, users can remove the ability to escalate
  privileges using this flaw by configuring core files to dump to an absolute
  location. By default, core files are created in the working directory of
  the faulting application, but this can be overridden by specifying an
  absolute location for core files in /proc/sys/kernel/core_pattern. To
  avoid a potential denial of service, a separate partition for the core
  files should be used.

  All Red Hat Enterprise Linux 4 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0574.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the   kernel packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-2.6.9-34.0.2.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-34.0.2.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-34.0.2.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-34.0.2.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-34.0.2.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-34.0.2.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-34.0.2.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-2451", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0574", value:TRUE);
