#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:063-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14046);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0012");
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0189", "CVE-2003-0245");
 
 name["english"] = "MDKSA-2003:063-1: apache2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:063-1 (apache2).


Two vulnerabilities were discovered in the Apache web server that affect all 2.x
versions prior to 2.0.46. The first, discovered by John Hughes, is a build
system problem that allows remote attackers to prevent access to authenticated
content when a threaded server is used. This only affects versions of Apache
compiled with threaded server 'httpd.worker', which is not the default for
Mandrake Linux.
The second vulnerability, discovered by iDefense, allows remote attackers to
cause a DoS (Denial of Service) condition and may also allow the execution of
arbitrary code.
The provided packages include back-ported fixes to correct these vulnerabilities
and MandrakeSoft encourages all users to upgrade immediately.
Update:
The previous update mistakenly listed apache-conf packages which were never
included, nor intended to be included, as part of the update.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:063-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the apache2 package";
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
if ( rpm_check( reference:"apache2-2.0.45-4.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-common-2.0.45-4.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-devel-2.0.45-4.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-manual-2.0.45-4.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_dav-2.0.45-4.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_ldap-2.0.45-4.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_ssl-2.0.45-4.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-modules-2.0.45-4.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-source-2.0.45-4.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libapr0-2.0.45-4.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"apache2-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0189", value:TRUE);
 set_kb_item(name:"CVE-2003-0245", value:TRUE);
}
