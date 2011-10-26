#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15944);
 script_version ("$Revision: 1.5 $");
 if (NASL_LEVEL >= 2200) script_cve_id("CVE-2004-0136", "CVE-2004-0619", "CVE-2004-0685", "CVE-2004-0812", "CVE-2004-0883", "CVE-2004-0949", "CVE-2004-1068", "CVE-2004-1070", "CVE-2004-1071", "CVE-2004-1072", "CVE-2004-1073");

 name["english"] = "RHSA-2004-549:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
 Updated kernel packages that fix several security issues in Red Hat                         
 Enterprise Linux 3 are now available.                                                       

 The Linux kernel handles the basic functions of the operating system.                       

 This update includes fixes for several security issues.

 All Red Hat Enterprise Linux 3 users are advised to upgrade their                           
 kernels to the packages associated with their machine architectures                         
 and configurations as listed in this erratum.                                               

Solution : http://rhn.redhat.com/errata/RHSA-2004-549.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the   kernel packages";
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
if ( rpm_check( reference:"kernel-2.4.21-20.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-20.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-20.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-20.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-20.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-20.0.1.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  kernel-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0136", value:TRUE);
 set_kb_item(name:"CVE-2004-0619", value:TRUE);
 set_kb_item(name:"CVE-2004-0685", value:TRUE);
 set_kb_item(name:"CVE-2004-0812", value:TRUE);
 set_kb_item(name:"CVE-2004-0883", value:TRUE);
 set_kb_item(name:"CVE-2004-0949", value:TRUE);
 set_kb_item(name:"CVE-2004-1068", value:TRUE);
 set_kb_item(name:"CVE-2004-1070", value:TRUE);
 set_kb_item(name:"CVE-2004-1071", value:TRUE);
 set_kb_item(name:"CVE-2004-1072", value:TRUE);
 set_kb_item(name:"CVE-2004-1073", value:TRUE);
}

set_kb_item(name:"RHSA-2004-549", value:TRUE);
