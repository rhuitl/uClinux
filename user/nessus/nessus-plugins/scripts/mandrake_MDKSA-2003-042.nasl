#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:042-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14026);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-b-0003");
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(7230);
 script_cve_id("CVE-2003-0161");
 
 name["english"] = "MDKSA-2003:042-1: sendmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:042-1 (sendmail).


Michal Zalweski discovered a vulnerability in sendmail versions earlier than
8.12.9 in the address parser, which performs insufficient bounds checking in
certain conditions due to a char to int conversion. This vulnerability makes it
poissible for an attacker to take control of sendmail and is thought to be
remotely exploitable, and very likely locally exploitable. Updated packages are
available with patches applied (the older versions), and the new fixed version
is available for Mandrake Linux 9.1 users.
Update:
The packages for Mandrake Linux 9.1 and 9.1/PPC were not GPG-signed. This has
been fixed and as a result the md5sums have changed. Thanks to Mark Lyda for
pointing this out.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:042-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sendmail package";
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
if ( rpm_check( reference:"sendmail-8.12.9-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.12.9-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.9-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.12.9-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"sendmail-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0161", value:TRUE);
}
