#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19471);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Fedora Core 4 2005-768: epiphany";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-768 (epiphany).

epiphany is a simple GNOME web browser based on the Mozilla rendering
engine


* Wed Aug 17 2005 Marco Pesenti Gritti <mpg@redhat.com> -  1.6.5-1
- Update to 1.6.5
- Remove patch integrated upstream



Solution : http://fedoranews.org//mediawiki/index.php/Fedora_Core_4_Update:_epiphany-1.6.5-1
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
if ( rpm_check( reference:"epiphany-1.6.5-1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"epiphany-devel-1.6.5-1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
