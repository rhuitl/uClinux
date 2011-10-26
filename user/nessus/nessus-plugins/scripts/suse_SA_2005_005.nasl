#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:005
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16362);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2005:005: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:005 (kernel).


The linux kernel is the core of the SUSE Linux based products.

Two weeks ago we released the Service Pack 1 for our SUSE Linux
Enterprise Server 9 product. Due to the strict code freeze we were
not able to merge all the security fixes from the last kernel update

Solution : http://www.suse.de/security/advisories/2005_05_kernel.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-source-2.6.5-7.145", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.5-7.145", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.5-7.145", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.5-7.145", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ltmodem-2.6.2-38.12", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
