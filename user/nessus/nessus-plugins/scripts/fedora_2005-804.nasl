#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19665);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Fedora Core 3 2005-804: epiphany";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-804 (epiphany).

epiphany is a simple GNOME web browser based on the Mozilla rendering
engine


* Thu Aug 18 2005 Marco Pesenti Gritti <mpg redhat com> 1.4.9-0
- Update to 1.4.9
- Remove download patch (integrated upstream)
- Add the manual to the package




Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the epiphany package";
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
if ( rpm_check( reference:"epiphany-1.4.9-0", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"epiphany-devel-1.4.9-0", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
