#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:016
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14001);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2003:016: util-linux";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:016 (util-linux).


The util-linux package provides the mcookie utility, a tool for generating
random cookies that can be used for X authentication. The util-linux packages
that were distributed with Mandrake Linux 8.2 and 9.0 had a patch that made it
use /dev/urandom instead of /dev/random, which resulted in the mcookie being
more predictable than it would otherwise be. This patch has been removed in
these updates, giving mcookie a better source of entropy and making the
generated cookies less predictable. Thanks to Dirk Mueller for pointing this
out.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:016
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the util-linux package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"losetup-2.11n-4.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mount-2.11n-4.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"util-linux-2.11n-4.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"losetup-2.11u-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mount-2.11u-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"util-linux-2.11u-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
