#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18128);
 script_version ("$Revision: 1.2 $");
# script_cve_id("CVE-2004-0075", "CVE-2004-0177", "CVE-2004-0814", "CVE-2004-1058", "CVE-2004-1073", "CVE-2005-0135", "CVE-2005-0137", "CVE-2005-0204", "CVE-2005-0384", "CVE-2005-0403", "CVE-2005-0449", "CVE-2005-0736", "CVE-2005-0749", "CVE-2005-0750");

 name["english"] = "RHSA-2005-293:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that fix several security issues in the Red Hat
  Enterprise Linux 3 kernel are now available.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  Red Hat Enterprise Linux 3 users are advised to upgrade their kernels to
  the packages associated with their machine architectures/configurations

  Please note that the fix for CVE-2005-0449 required changing the
  external symbol linkages (kernel module ABI) for the ip_defrag()
  and ip_ct_gather_frags() functions. Any third-party module using either
  of these would also need to be fixed.




Solution : http://rhn.redhat.com/errata/RHSA-2005-293.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the   kernel packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-2.4.21-27.0.4.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-27.0.4.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-27.0.4.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-hugemem-2.4.21-27.0.4.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-hugemem-unsupported-2.4.21-27.0.4.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-27.0.4.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-27.0.4.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"  kernel-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0075", value:TRUE);
 set_kb_item(name:"CVE-2004-0177", value:TRUE);
 set_kb_item(name:"CVE-2004-0814", value:TRUE);
 set_kb_item(name:"CVE-2004-1058", value:TRUE);
 set_kb_item(name:"CVE-2004-1073", value:TRUE);
 set_kb_item(name:"CVE-2005-0135", value:TRUE);
 set_kb_item(name:"CVE-2005-0137", value:TRUE);
 set_kb_item(name:"CVE-2005-0204", value:TRUE);
 set_kb_item(name:"CVE-2005-0384", value:TRUE);
 set_kb_item(name:"CVE-2005-0403", value:TRUE);
 set_kb_item(name:"CVE-2005-0449", value:TRUE);
 set_kb_item(name:"CVE-2005-0736", value:TRUE);
 set_kb_item(name:"CVE-2005-0749", value:TRUE);
 set_kb_item(name:"CVE-2005-0750", value:TRUE);
}

set_kb_item(name:"RHSA-2005-293", value:TRUE);
