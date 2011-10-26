#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:084
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13982);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1320");
 
 name["english"] = "MDKSA-2002:084: pine";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:084 (pine).


A vulnerability was discovered in pine while parsing and escaping characters of
email addresses; not enough memory is allocated for storing the escaped mailbox
part of the address. The resulting buffer overflow on the heap makes pine crash.
This new version of pine, 4.50, has the vulnerability fixed. It also offers many
other bug fixes and new features.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:084
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pine package";
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
if ( rpm_check( reference:"pine-4.50-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pine-4.50-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pine-4.50-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pine-4.50-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"pine-", release:"MDK7.2")
 || rpm_exists(rpm:"pine-", release:"MDK8.0")
 || rpm_exists(rpm:"pine-", release:"MDK8.1")
 || rpm_exists(rpm:"pine-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-1320", value:TRUE);
}
