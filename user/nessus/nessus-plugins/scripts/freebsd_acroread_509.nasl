#
# (C) Tenable Network Security
#
#
if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14266);
 #script_bugtraq_id();
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0630");
 name["english"] = "FreeBSD Ports : Acroread uudecoding vulnerability";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Acroread less than or equal 
to 0.21.1_2.

Acroread is a PDF reader for BSD.

This version of Acroread is reported as being vulnerable to a 
bug wherein the application crashes during a uudecode of a
file.  An attacker, exploiting this flaw, would need to be
able to coerce a local user into opening a malicious file (perhaps
via email or WWW).

Solution : http://www.vuxml.org/freebsd/78348ea2-ec91-11d8-b913-000c41e2cdad.html 
 
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the Acroread package";
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
package = egrep(pattern:"^acroread-", string:pkgs);
if ( package && pkg_cmp(pkg:package, reference:"acroread-5.0.9") < 0 )
        security_warning(0);

