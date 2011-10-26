#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12442);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0476");

 name["english"] = "RHSA-2003-408: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that address various security vulnerabilities, fix
  a
  number of bugs, and update various drivers are now available.

  The Linux kernel handles the basic functions of the operating system.

  The execve system call in Linux 2.4.x records the file descriptor of the
  executable process in the file table of the calling process, which allows
  local users to gain read access to restricted file descriptors. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2003-0476 to this issue.

  A number of bugfixes are included, including important fixes for the ext3
  file system and timer code.

  New features include limited support for non-cached NFS file sytems, Serial
  ATA (SATA) devices, and new alt-sysreq debugging options.

  In addition, the following drivers have been updated:

  - e100 2.3.30-k1
  - e1000 5.2.20-k1
  - fusion 2.05.05+
  - ips 6.10.52
  - aic7xxx 6.2.36
  - aic79xxx 1.3.10
  - megaraid 2 2.00.9
  - cciss 2.4.49

  All users are advised to upgrade to these erratum packages, which contain
  backported patches addressing these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2003-408.html
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
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.34", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.34", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.34", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.34", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0476", value:TRUE);
}

set_kb_item(name:"RHSA-2003-408", value:TRUE);
