#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:090
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13903);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2001:090: wu-ftpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:090 (wu-ftpd).


A vulnerability in wu-ftpd's ftpglob() function was found by the CORE ST team.
This vulnerability can be exploited to obtain root access on the FTP server.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:090
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wu-ftpd package";
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
if ( rpm_check( reference:"wu-ftpd-2.6.1-8.7mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wu-ftpd-2.6.1-8.8mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wu-ftpd-2.6.1-11.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wu-ftpd-2.6.1-11.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
