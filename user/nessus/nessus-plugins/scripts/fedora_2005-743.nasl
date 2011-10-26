#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19437);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Fedora Core 4 2005-743: evolution";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-743 (evolution).

Evolution is the GNOME collection of personal information management
(PIM) tools.

Evolution includes a mailer, calendar, contact manager and
communication facility.  The tools which make up Evolution will be
tightly integrated with one another and act as a seamless personal
information-management tool.

Update Information:

Fix for SITIC Vulnerability Advisory SA05-001


Solution : http://fedoranews.org//mediawiki/index.php/Fedora_Core_4_Update:_evolution-2.2.3-2.fc4
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the evolution package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"evolution-2.2.3-2.fc4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-2.2.3-2.fc4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
