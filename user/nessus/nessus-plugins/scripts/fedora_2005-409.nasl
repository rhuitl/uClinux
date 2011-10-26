#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18576);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Fedora Core 4 2005-409: elinks";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-409 (elinks).

Links is a text-based Web browser. Links does not display any images,
but it does support frames, tables and most other HTML tags. Links'
advantage over graphical browsers is its speed--Links starts and exits
quickly and swiftly displays Web pages.


* Sat Jun 11 2005 Karel Zak <kzak redhat com> 0.10.3-3.1

- fix #159575 - elinks fails to render entire page




Solution : http://www.redhat.com/archives/fedora-announce-list/2005-June/msg00013.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the elinks package";
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
if ( rpm_check( reference:"elinks-0.10.3-3.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
