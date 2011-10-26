#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:072
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14055);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0251");
 
 name["english"] = "MDKSA-2003:072: ypserv";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:072 (ypserv).


A vulnerability was found in versions of ypserv prior to version 2.7. If a
malicious client were to query ypserv via TCP and subsequently ignore the
server's response, ypserv will block attempting to send the reply. The result is
that ypserv will fail to respond to other client requests. ypserv 2.7 and above
have been altered to fork a child for each client request, which prevents any
one request from causing the server to block.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:072
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
if ( rpm_check( reference:"ypserv-2.8-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ypserv-2.8-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ypserv-", release:"MDK8.2")
 || rpm_exists(rpm:"ypserv-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0251", value:TRUE);
}
