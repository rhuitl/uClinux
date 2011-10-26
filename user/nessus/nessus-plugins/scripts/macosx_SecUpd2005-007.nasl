#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19463);
 script_bugtraq_id(14567);
 script_version ("$Revision: 1.1 $");
 name["english"] = "Mac OS X Security Update 2005-007";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2005-007. This security
update contains security fixes for the following applications :

- Apache 2
- AppKit
- Bluetooth
- CoreFoundation
- CUPS
- Directory Services
- HItoolbox
- Kerberos
- loginwindow
- Mail
- MySQL
- OpenSSL
- QuartzComposerScreenSaver
- ping
- Safari
- SecurityInterface
- servermgrd
- servermgr_ipfilter
- SquirelMail
- traceroute
- WebKit
- WebLog Server
- X11
- zlib


Solution : http://docs.info.apple.com/article.html?artnum=302163
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2005-007";
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
# MacOS X 10.4.2
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.2\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2005-007", string:packages)) security_hole(0);
}
