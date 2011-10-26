#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:011
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13919);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:011: gzip";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:011 (gzip).


There are two problems with the gzip archiving program; the first is a crash
when an input file name is over 1020 characters, and the second is a buffer
overflow that could be exploited if gzip is run on a server such as an FTP
server. The patch applied is from the gzip developers and the problems have been
fixed in the latest beta.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:011
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gzip package";
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
if ( rpm_check( reference:"gzip-1.2.4a-9.2mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gzip-1.2.4a-9.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gzip-1.2.4a-9.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gzip-1.2.4a-9.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
