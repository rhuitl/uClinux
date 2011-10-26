#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:022
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20816);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-1349");
 
 name["english"] = "MDKSA-2006:022: perl-Convert-UUlib";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:022 (perl-Convert-UUlib).



A buffer overflow was discovered in the perl Convert::UUlib module in versions
prior to 1.051, which could allow remote attackers to execute arbitrary code
via a malformed parameter to a read operation. This update provides version
1.051 which is not vulnerable to this flaw.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:022
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the perl-Convert-UUlib package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"perl-Convert-UUlib-1.051-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"perl-Convert-UUlib-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1349", value:TRUE);
}
