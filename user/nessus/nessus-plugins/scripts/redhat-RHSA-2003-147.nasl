#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12390);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0244", "CVE-2003-0246");

 name["english"] = "RHSA-2003-147: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  These updated kernel packages address security vulnerabilites, including
  two possible data corruption scenarios. In addition, a number of
  drivers have been updated, improvements made to system performance, and
  various issues have been resolved.

  A flaw was found in several hash table implementations in the kernel
  networking code. A remote attacker sending packets with carefully
  chosen, forged source addresses could potentially cause every routing
  cache entry to be hashed into the same hash chain. As a result, the kernel
  would use a disproportionate amount of processor time to deal
  with the new packets, leading to a remote denial-of-service (DoS) attack.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2003-0244 to this issue.

  A flaw was also found in the "ioperm" system call, which fails to properly
  restrict privileges. This flaw can allow an unprivileged local user to gain
  read and write access to I/O ports on the system. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2003-0246 to this issue.


  All users should upgrade to these errata packages, which address these
  issues.




Solution : http://rhn.redhat.com/errata/RHSA-2003-147.html
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
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.24", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.24", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.24", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.24", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0244", value:TRUE);
 set_kb_item(name:"CVE-2003-0246", value:TRUE);
}

set_kb_item(name:"RHSA-2003-147", value:TRUE);
