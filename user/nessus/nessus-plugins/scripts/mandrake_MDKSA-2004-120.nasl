#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:120
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15600);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0982");
 
 name["english"] = "MDKSA-2004:120: mpg123";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:120 (mpg123).



Carlos Barros discovered two buffer overflow vulnerabilities in mpg123; the
first in the getauthfromURL() function and the second in the http_open()
function. These vulnerabilities could be exploited to possibly execute
arbitrary code with the privileges of the user running mpg123.

The provided packages are patched to fix these issues, as well additional
boundary checks that were lacking have been included (thanks to the Gentoo
Linux Sound Team for these additional fixes).



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:120
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mpg123 package";
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
if ( rpm_check( reference:"mpg123-0.59r-22.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mpg123-0.59r-22.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mpg123-", release:"MDK10.0")
 || rpm_exists(rpm:"mpg123-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-0982", value:TRUE);
}
