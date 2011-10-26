#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14280);
 script_bugtraq_id(10946);
 script_version ("$Revision: 1.6 $");

 name["english"] = "FreeBSD Ruby CGI vulnerability";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running an older version of Ruby.

Ruby is an object-oriented scripting language.

Based on the version number, it is possible that the
version of Ruby is vulnerable to a local attack.  That is,
this version of Ruby creates files with permissions such that
any local user can overwrite the file content.  An attacker,
exploiting this flaw, would need local access and the ability
to know where a specific Ruby script is writing files.

Solution :  http://www.vuxml.org/freebsd/e811aaf1-f015-11d8-876f-00902714cc7c.html
 
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "FreeBSD Ruby CGI vulnerability detection";
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
package = egrep(pattern:"^ruby-", string:pkgs);
if ( package && pkg_cmp(pkg:package, reference:"ruby-1.8.1.2004.07.23") < 0 )
        security_warning(0);

