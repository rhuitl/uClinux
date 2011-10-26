#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:058
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14157);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0414", "CVE-2004-0416", "CVE-2004-0417", "CVE-2004-0418");
 
 name["english"] = "MDKSA-2004:058: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:058 (cvs).


Another vulnerability was discovered related to 'Entry' lines in cvs, by the
development team (CVE-2004-0414).
As well, Stefan Esser and Sebastian Krahmer performed an audit on the cvs source
code and discovered a number of other problems, including:
A double-free condition in the server code is exploitable (CVE-2004-0416).
By sending a large number of arguments to the CVS server, it is possible to
cause it to allocate a huge amount of memory which does not fit into the address
space, causing an error (CVE-2004-0417).
It was found that the serve_notify() function would write data out of bounds
(CVE-2004-0418).
The provided packages update cvs to 1.11.16 and include patches to correct all
of these problems.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:058
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cvs package";
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
if ( rpm_check( reference:"cvs-1.11.16-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.16-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.16-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cvs-", release:"MDK10.0")
 || rpm_exists(rpm:"cvs-", release:"MDK9.1")
 || rpm_exists(rpm:"cvs-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0414", value:TRUE);
 set_kb_item(name:"CVE-2004-0416", value:TRUE);
 set_kb_item(name:"CVE-2004-0417", value:TRUE);
 set_kb_item(name:"CVE-2004-0418", value:TRUE);
}
