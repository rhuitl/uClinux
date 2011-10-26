#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19658);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Fedora Core 3 2005-367: htdig";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-367 (htdig).

The ht://Dig system is a complete world wide web indexing and searching
system for a small domain or intranet. This system is not meant to replace
the need for powerful internet-wide search systems like Lycos, Infoseek,
Webcrawler and AltaVista. Instead it is meant to cover the search needs for
a single company, campus, or even a particular sub section of a web site. As
opposed to some WAIS-based or web-server based search engines, ht://Dig can
span several web servers at a site. The type of these different web servers
doesn't matter as long as they understand the HTTP 1.0 protocol.
ht://Dig is also used by KDE to search KDE's HTML documentation.

ht://Dig was developed at San Diego State University as a way to search the
various web servers on the campus network.

* Tue Apr 19 2005 Phil Knirsch <pknirsch redhat com> 3:3.2.0b6-3.FC3.1
- Fixed security bug with unescaped output in htsearch and qtest (#144127)
- Removed .la and .a libs from package (#145649)



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the htdig package";
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
if ( rpm_check( reference:"htdig-3.2.0b6-3.FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"htdig-web-3.2.0b6-3.FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"htdig-debuginfo-3.2.0b6-3.FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
