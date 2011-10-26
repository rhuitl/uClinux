#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:078
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13976);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1232");
 
 name["english"] = "MDKSA-2002:078: ypserv";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:078 (ypserv).


A memory leak that could be triggered remotely was discovered in ypserv 2.5 and
earlier. This could lead to a Denial of Service as repeated requests for a
non-existant map will result in ypserv consuming more and more memory, and also
running more slowly. If the system runs out of available memory, ypserv would
also be killed.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:078
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ypserv package";
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
if ( rpm_check( reference:"ypserv-1.3.12-3.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ypserv-1.3.12-3.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ypserv-1.3.12-3.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ypserv-2.5-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ypserv-2.5-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ypserv-", release:"MDK7.2")
 || rpm_exists(rpm:"ypserv-", release:"MDK8.0")
 || rpm_exists(rpm:"ypserv-", release:"MDK8.1")
 || rpm_exists(rpm:"ypserv-", release:"MDK8.2")
 || rpm_exists(rpm:"ypserv-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1232", value:TRUE);
}
