#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14242);
 script_bugtraq_id(10857);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0597","CVE-2004-0598","CVE-2004-0599");
 name["english"] = "Mac OS X Security Update 2004-08-09";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2004-08-09.

Libpng is a library used for manipulating graphics files.

Several buffer overflows have been discovered in libpng. An attacker
could create a carefully crafted PNG file in such a way that it would
cause an application linked with libpng to execute arbitrary code when
the file was opened by a victim.


Solution : http://docs.info.apple.com/article.html?artnum=61798
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2004-08-09";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# MacOS X 10.2.x and 10.3.x only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.4\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd2004-08-09", string:packages) ) security_hole(0);
}
