#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:195
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20123);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-3258");
 
 name["english"] = "MDKSA-2005:195: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:195 (squid).



The rfc1738_do_escape function in ftp.c for Squid 2.5.STABLE11 and earlier
allows remote FTP servers to cause a denial of service (segmentation fault) via
certain 'odd' responses. The updated packages have been patched to address
these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:195
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid package";
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
if ( rpm_check( reference:"squid-2.5.STABLE9-1.5.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE9-1.5.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE10-10.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-cachemgr-2.5.STABLE10-10.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"squid-", release:"MDK10.1")
 || rpm_exists(rpm:"squid-", release:"MDK10.2")
 || rpm_exists(rpm:"squid-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3258", value:TRUE);
}
