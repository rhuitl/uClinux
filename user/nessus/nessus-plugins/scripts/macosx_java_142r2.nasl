#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19702);
 script_bugtraq_id(14825, 14826, 14827);
 name["english"] = "Mac OS X : Java 1.3.1 and 1.4.2 Release 2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing a security bugfix for Java 1.4.2 and 1.3.1.

This update fixes several security vulnerabilities which may allow
a java applet to escalate its privileges. 

To exploit these flaws, an attacker would need to lure an attacker
into executing a rogue Java applet.

Solution : http://docs.info.apple.com/article.html?artnum=302266
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Java 1.4.2";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# MacOS X 10.3.9 and 10.4.2 only
if ( egrep(pattern:"Darwin.* 7\.[0-9]\.", string:uname) )
{
  if ( !egrep(pattern:"^JavaSecurityUpdate4\.pkg", string:packages) ) security_hole(0);
}
else if ( egrep(pattern:"Darwin.* 8\.[0-2]\.", string:uname) )
{
  if ( !egrep(pattern:"^Java131and142Release2\.pkg", string:packages) ) security_hole(0);
}
