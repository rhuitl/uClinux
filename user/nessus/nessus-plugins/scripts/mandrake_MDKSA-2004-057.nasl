#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:057-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14156);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(10454);
 script_cve_id("CVE-2004-0536");
 
 name["english"] = "MDKSA-2004:057-1: tripwire";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:057-1 (tripwire).


Paul Herman discovered a format string vulnerability in tripwire that could
allow a local user to execute arbitrary code with the rights of the user running
tripwire (typically root). This vulnerability only exists when tripwire is
generating an email report.
Update:
The packages previously released for Mandrakelinux 9.2 would segfault when doing
a check due to compilation problems. The updated packages correct the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:057-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tripwire package";
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
if ( rpm_check( reference:"tripwire-2.3.1.2-7.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"tripwire-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0536", value:TRUE);
}
