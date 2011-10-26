#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:037
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15528);
 script_version ("$Revision: 1.3 $");
 script_bugtraq_id(11488, 11489);
 script_cve_id("CVE-2004-0816", "CVE-2004-0887");
 
 name["english"] = "SUSE-SA:2004:037: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2004:037 (kernel).


An integer underflow problem in the iptables firewall logging rules
can allow a remote attacker to crash the machine by using a handcrafted
IP packet. This attack is only possible with firewalling enabled.

We would like to thank Richard Hart for reporting the problem.

This problem has already been fixed in the 2.6.8 upstream Linux kernel,
this update contains a backport of the fix.

Products running a 2.4 kernel are not affected.

Mitre has assigned the CVE ID CVE-2004-0816 for this problem.


Additionaly Martin Schwidefsky of IBM found an incorrectly handled
privileged instruction which can lead to a local user gaining
root user privileges.

This only affects the SUSE Linux Enterprise Server 9 on the S/390
platform and has been assigned CVE ID CVE-2004-0887.


Additionaly the following non-security bugs were fixed:

- Two CD burning problems.

- USB 2.0 stability problems under high load on SMP systems.

- Several SUSE Linux Enterprise Server issues.
(see the Maintenance Information Mail for more informations).



Solution : http://www.suse.de/security/2004_37_kernel.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-default-2.6.5-7.111", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.5-7.111", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.5-7.111", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0816", value:TRUE);
 set_kb_item(name:"CVE-2004-0887", value:TRUE);
}
