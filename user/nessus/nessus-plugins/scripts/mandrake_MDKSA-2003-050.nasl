#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:050
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14034);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0020", "CVE-2003-0083", "CVE-2003-0132");
 
 name["english"] = "MDKSA-2003:050: apache2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:050 (apache2).


A memory leak was discovered in Apache 2.0 through 2.0.44 that can allow a
remote attacker to cause a significant denial of service (DoS) by sending
requests containing a lot of linefeed characters to the server.
As well, Apache does not filter terminal escape sequences from its log files,
which could make it easy for an attacker to insert those sequences into the
error and access logs, which could possibly be viewed by certain terminal
emulators with vulnerabilities related to escape sequences.
After upgrading these packages, be sure to restart the httpd server by
executing:
service httpd restart


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:050
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
if ( rpm_check( reference:"apache2-2.0.45-4.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-common-2.0.45-4.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-devel-2.0.45-4.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-manual-2.0.45-4.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_dav-2.0.45-4.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_ldap-2.0.45-4.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_ssl-2.0.45-4.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-modules-2.0.45-4.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-source-2.0.45-4.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libapr0-2.0.45-4.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"apache2-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0020", value:TRUE);
 set_kb_item(name:"CVE-2003-0083", value:TRUE);
 set_kb_item(name:"CVE-2003-0132", value:TRUE);
}
