#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:083
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13896);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2001:083: htdig";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:083 (htdig).


A problem was discovered in the ht://Dig web indexing and searching program.
Nergal reported a vulnerability in htsearch that allows a remote user to pass
the -c parameter, to use a specific config file, to the htsearch program when
running as a CGI. A malicious user could point to a file like /dev/zero and
force the CGI to stall until it times out. Repeated attacks could result in a
DoS. As well, if the user has write permission on the server and can create a
file with certain entries, they can point the server to it and retrieve any file
readable by the webserver UID.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:083
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the htdig package";
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
if ( rpm_check( reference:"htdig-3.1.5-6.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"htdig-3.1.5-9.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"htdig-3.2.0-0.5mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"htdig-devel-3.2.0-0.5mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"htdig-web-3.2.0-0.5mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
