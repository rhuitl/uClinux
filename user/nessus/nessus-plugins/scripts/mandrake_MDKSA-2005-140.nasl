#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:140
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19897);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2390");
 
 name["english"] = "MDKSA-2005:140: proftpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:140 (proftpd).



Two format string vulnerabilities were discovered in ProFTPD. The first exists
when displaying a shutdown message containin the name of the current directory.
This could be exploited by a user who creates a directory containing format
specifiers and sets the directory as the current directory when the shutdown
message is being sent.

The second exists when displaying response messages to the cleint using
information retreived from a database using mod_sql. Note that mod_sql support
is not enabled by default, but the contrib source file has been patched
regardless.

The updated packages have been patched to correct these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:140
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the proftpd package";
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
if ( rpm_check( reference:"proftpd-1.2.9-3.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"proftpd-anonymous-1.2.9-3.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"proftpd-1.2.10-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"proftpd-anonymous-1.2.10-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"proftpd-1.2.10-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"proftpd-anonymous-1.2.10-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"proftpd-", release:"MDK10.0")
 || rpm_exists(rpm:"proftpd-", release:"MDK10.1")
 || rpm_exists(rpm:"proftpd-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2390", value:TRUE);
}
