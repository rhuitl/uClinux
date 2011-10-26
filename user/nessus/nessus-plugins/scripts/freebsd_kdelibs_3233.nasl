#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14268);
 script_bugtraq_id(10921, 10922, 10924);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0721");

 name["english"] = "FreeBSD Ports : kdelibs less than 3.2.3_3";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running a version of kdelibs prior to 3.2.3_3.
kdelibs is part of the KDE program.  KDE includes a web-browser,
Konqueror, which is vulnerable to a remote cross-site scripting
attack.  An attacker, exploiting this flaw, would need to be 
able to coerce a local user into connecting to a malicious site.

Solution : http://www.vuxml.org/freebsd/641859e8-eca1-11d8-b913-000c41e2cdad.html

Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}



include("freebsd_package.inc");


pkgs = get_kb_item("Host/FreeBSD/pkg_info");
package = egrep(pattern:"^kdelibs-", string:pkgs);
if ( package && pkg_cmp(pkg:package, reference:"kdelibs-3.2.3_3") < 0 )
        security_warning(0);

package = egrep(pattern:"^kdebase-", string:pkgs);
if ( package && pkg_cmp(pkg:package, reference:"kdebase-3.2.3_1") < 0 )
        security_warning(0);



