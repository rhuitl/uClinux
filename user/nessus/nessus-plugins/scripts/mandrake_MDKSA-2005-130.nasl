#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:130
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19890);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2088");
 
 name["english"] = "MDKSA-2005:130: apache";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:130 (apache).



Watchfire reported a flaw that occured when using the Apache server as a HTTP
proxy. A remote attacker could send an HTTP request with both a
'Transfer-Encoding: chunked' header and a 'Content-Length' header which would
cause Apache to incorrectly handle and forward the body of the request in a way
that the receiving server processed it as a separate HTTP request. This could
be used to allow the bypass of web application firewall protection or lead to
cross-site scripting (XSS) attacks (CVE-2005-2088).

The updated packages have been patched to prevent these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:130
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the apache package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"apache-1.3.29-1.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-devel-1.3.29-1.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-modules-1.3.29-1.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-source-1.3.29-1.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-1.3.31-7.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-devel-1.3.31-7.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-modules-1.3.31-7.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-source-1.3.31-7.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-1.3.33-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-devel-1.3.33-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-modules-1.3.33-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache-source-1.3.33-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"apache-", release:"MDK10.0")
 || rpm_exists(rpm:"apache-", release:"MDK10.1")
 || rpm_exists(rpm:"apache-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2088", value:TRUE);
}
