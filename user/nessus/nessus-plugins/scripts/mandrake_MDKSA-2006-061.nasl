#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:061
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21176);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0052");
 
 name["english"] = "MDKSA-2006:061: mailman";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:061 (mailman).



Scrubber.py, in Mailman 2.1.5 and earlier, when using email 2.5 (part of
Python), is susceptible to a DoS (mailman service stops delivering for the list
in question) if it encounters a badly formed mime multipart message with only
one part and that part has two blank lines between the first boundary and the
end boundary. Updated packages have been patched to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:061
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mailman package";
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
if ( rpm_check( reference:"mailman-2.1.5-15.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mailman-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2006-0052", value:TRUE);
}
