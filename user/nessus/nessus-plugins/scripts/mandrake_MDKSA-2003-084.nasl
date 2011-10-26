#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:084
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14066);
 script_bugtraq_id(8231);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0615");
 
 name["english"] = "MDKSA-2003:084: perl-CGI";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:084 (perl-CGI).


Eye on Security found a cross-site scripting vulnerability in the start_form()
function in CGI.pm. This vulnerability allows a remote attacker to place a web
script in a URL which feeds into a form's action parameter and allows execution
by the browser as if it was coming from the site.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:084
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the perl-CGI package";
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
if ( rpm_check( reference:"perl-CGI-3.00-0.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-CGI-3.00-0.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-CGI-3.00-0.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"perl-CGI-", release:"MDK8.2")
 || rpm_exists(rpm:"perl-CGI-", release:"MDK9.0")
 || rpm_exists(rpm:"perl-CGI-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0615", value:TRUE);
}
