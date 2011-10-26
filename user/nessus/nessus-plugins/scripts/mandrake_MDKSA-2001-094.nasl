#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:094
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13907);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2001:094: libgtop";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:094 (libgtop).


A remote format string vulnerability was found in the libgtop daemon by
Laboratory intexxia. By sending a specially crafted format string to the server,
a remote attacker could potentially execute arbitrary code on the remote system
with the daemon's permissions. By default libgtop runs as the user nobody, but
the flaw could be used to compromise local system security by allowing the
attacker to exploit other local vulnerabilities. A buffer overflow was also
found by Flavio Veloso which could allow the client to execute code on the
server. Both vulnerabilities are patched in this update and will be fixed
upstream in version 1.0.14. libgtop_daemon is not invoked by default anywhere in
Mandrake Linux.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:094
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libgtop package";
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
if ( rpm_check( reference:"libgtop-1.0.7-0.2mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtop-devel-1.0.7-0.2mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtop-1.0.9-5.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtop-devel-1.0.9-5.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtop1-1.0.12-4.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtop1-devel-1.0.12-4.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtop1-1.0.12-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtop1-devel-1.0.12-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
