#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:055-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13872);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "MDKSA-2001:055-1: xinetd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:055-1 (xinetd).


A bug exists in xinetd as shipped with Mandrake Linux 8.0 dealing with TCP
connections with the WAIT state that prevents linuxconf-web from working
properly. As well, xinetd contains a security flaw in which it defaults to a
umask of 0. This means that applications using the xinetd umask that do not set
permissions themselves (like SWAT, a web configuration tool for Samba), will
create world writable files. This update sets the default umask to 022.
Update:
This update forces the TMPDIR to /tmp instead of obtaining it from the root user
by default, which uses /root/tmp. As well, this version of xinetd also fixed a
possible buffer overflow in the logging code that was reported by zen-parse on
bugtraq, but was not mentioned in the previous advisory.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:055-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xinetd package";
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
if ( rpm_check( reference:"xinetd-2.3.0-1.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xinetd-2.3.0-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xinetd-ipv6-2.3.0-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
