#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:108
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14090);
 script_bugtraq_id(8537);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0740");
 
 name["english"] = "MDKSA-2003:108: stunnel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:108 (stunnel).


A vulnerability was discovered in stunnel versions 3.24 and earlier, as well as
4.00, by Steve Grubb. It was found that stunnel leaks a critical file descriptor
that can be used to hijack stunnel's services.
All users are encouraged to upgrade to these packages. Note that the version of
stunnel provided with Mandrake Linux 9.1 and above is not vulnerable to this
problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:108
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the stunnel package";
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
if ( rpm_check( reference:"stunnel-3.26-1.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"stunnel-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0740", value:TRUE);
}
