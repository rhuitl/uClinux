#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:052
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14036);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-a-0008");
 script_bugtraq_id(7178);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0209");
 
 name["english"] = "MDKSA-2003:052: snort";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:052 (snort).


An integer overflow was discovered in the Snort stream4 preprocessor by the
Sourcefire Vulnerability Research Team. This preprocessor (spp_stream4)
incorrectly calculates segment size parameters during stream reassembly for
certainm sequence number ranges. This can lead to an integer overflow that can
in turn lead to a heap overflow that can be exploited to perform a denial of
service (DoS) or even remote command excution on the host running Snort.
Disabling the stream4 preprocessor will make Snort invulnerable to this attack,
and the flaw has been fixed upstream in Snort version 2.0. Snort versions 1.8
through 1.9.1 are vulnerable.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:052
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the snort package";
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
if ( rpm_check( reference:"snort-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-bloat-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-mysql+flexresp-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-mysql-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-plain+flexresp-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-postgresql-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-snmp+flexresp-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-snmp-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-2.0.0-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-bloat-2.0.0-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-mysql+flexresp-2.0.0-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-mysql-2.0.0-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-plain+flexresp-2.0.0-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-postgresql-2.0.0-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-snmp+flexresp-2.0.0-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-snmp-2.0.0-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-2.0.0-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-bloat-2.0.0-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-mysql+flexresp-2.0.0-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-mysql-2.0.0-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-plain+flexresp-2.0.0-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-postgresql-2.0.0-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-snmp+flexresp-2.0.0-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"snort-snmp-2.0.0-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"snort-", release:"MDK8.2")
 || rpm_exists(rpm:"snort-", release:"MDK9.0")
 || rpm_exists(rpm:"snort-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0209", value:TRUE);
}
