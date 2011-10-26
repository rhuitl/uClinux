#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12510);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0497");

 name["english"] = "RHSA-2004-354: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that fix a security vulnerability affecting the
  kernel nfs server for Red Hat Enterprise Linux 2.1 are now available.

  The Linux kernel handles the basic functions of the operating system.

  During an audit of the Linux kernel, SUSE discovered a flaw that allowed
  a user to make unauthorized changes to the group ID of files in certain
  circumstances. In the 2.4 kernel, as shipped with Red Hat Enterprise
  Linux, the only way this could happen is through the kernel nfs server. A
  user on a system that mounted a remote file system from a vulnerable
  machine may be able to make unauthorized changes to the group ID of
  exported files. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0497 to this issue.

  Only Red Hat Enterprise Linux systems that are configured to share file
  systems via NFS are affected by this issue.

  All Red Hat Enterprise Linux 2.1 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum. These packages contain a
  backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-354.html
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
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.43", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.43", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.43", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.43", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0497", value:TRUE);
}

set_kb_item(name:"RHSA-2004-354", value:TRUE);
