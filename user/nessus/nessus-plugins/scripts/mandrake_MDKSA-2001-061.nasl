#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:061-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13876);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "MDKSA-2001:061-1: gtk+";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:061-1 (gtk+).


A vulnerability exists with the GTK+ toolkit in that the GTK_MODULES environment
variable allows a local user to enter a directory path to a module that does not
necessarily need to be associated with GTK+. With this, an attacker could create
a custom module and load it using the toolkit which could result in elevated
privileges, the overwriting of system files, and the execution of malicious
code.
Update:
The packages for 7.2 and Single Network Firewall 7.2 were not signed with our
GnuPG key. Please note the changed MD5 values of the below packages.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:061-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gtk+ package";
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
if ( rpm_check( reference:"gtk+-1.2.8-6.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk+-devel-1.2.8-6.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+1.2-1.2.10-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+1.2-devel-1.2.10-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
