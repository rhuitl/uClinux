#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20884);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0645");
 
 name["english"] = "Fedora Core 4 2006-107: gnutls";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-107 (gnutls).

The GNU TLS library implements TLS.  Someone needs to fix this description.


* Fri Feb 10 2006 Martin Stransky <stransky redhat com> 1.0.25-2.FC4
- fix for CVE-2006-0645



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gnutls package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gnutls-1.0.25-2.FC4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gnutls-", release:"FC4") )
{
 set_kb_item(name:"CVE-2006-0645", value:TRUE);
}
