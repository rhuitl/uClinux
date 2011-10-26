#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:085
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14067);
 script_bugtraq_id(8469);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0547", "CVE-2003-0548", "CVE-2003-0549");
 
 name["english"] = "MDKSA-2003:085: gdm";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:085 (gdm).


Several vulnerabilities were discovered in versions of gdm prior to 2.4.1.6. The
first vulnerability is that any user can read any text file on the system due to
code originally written to be run as the user logging in was in fact being run
as the root user. This code is what allows the examination of the
~/.xsession-errors file. If a user makes a symlink from this file to any other
file on the system during the session and ensures that the session lasts less
than ten seconds, the user can read the file provided it was readable as a text
file.
Another two vulnerabilities were found in the XDMCP code that could be exploited
to crash the main gdm daemon which would inhibit starting any new sessions
(although the current session would be unaffected). The first problem here is
due to the indirect query structure being used right after being freed due to a
missing 'continue' statement in a loop; this happens if a choice of server
expired and the client tried to connect.
The second XDMCP problem is that when authorization data is being checked as a
string, the length is not checked first. If the data is less than 18 bytes long,
the daemon may wander off the end of the string a few bytes in the strncmp which
could cause a SEGV.
These updated packages bring gdm to version 2.4.1.6 which is not vulnerable to
any of these problems. Also note that XDMCP support is disabled by default in
gdm.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:085
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gdm package";
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
if ( rpm_check( reference:"gdm-2.4.1.6-0.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdm-Xnest-2.4.1.6-0.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdm-2.4.1.6-0.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdm-Xnest-2.4.1.6-0.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gdm-", release:"MDK9.0")
 || rpm_exists(rpm:"gdm-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0547", value:TRUE);
 set_kb_item(name:"CVE-2003-0548", value:TRUE);
 set_kb_item(name:"CVE-2003-0549", value:TRUE);
}
