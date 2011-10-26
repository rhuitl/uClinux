#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14768);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0873");
 script_bugtraq_id(11207);
 name["english"] = "Mac OS X Security Update 2004-09-16";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2004-09-16.

This security update iChat. There is a bug in older versions of iChat
where an attacker may execute commands on the local system by sending
malformed links which will execute local commands to an iChat user on 
the remote host.

Solution : http://docs.info.apple.com/article.html?artnum=61798
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2004-09-16";
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
# MacOS X 10.2.8, 10.3.4 and 10.3.5 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[45]\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd(Srvr)?2004-09-16", string:packages) ) security_hole(0);
}
