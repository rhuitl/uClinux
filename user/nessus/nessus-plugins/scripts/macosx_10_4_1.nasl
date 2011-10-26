#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18353);
 script_bugtraq_id(13694, 13695, 13696);
 script_cve_id("CVE-2005-1474");
 script_version ("$Revision: 1.7 $");
 name["english"] = "Mac OS X < 10.4.1";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Mac OS X 10.4 which is older than
version 10.4.1.

Mac OS X 10.4.1 contains several security fixes for :

- Bluetooth
- Dashboard
- Kernel
- SecurityAgent

Solution : http://docs.info.apple.com/article.html?artnum=301630
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of Mac OS X";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl", "mdns.nasl");
 #script_require_keys("Host/MacOSX/packages");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("mDNS/os");
if ( ! os ) exit(0);

if ( ereg(pattern:"Mac OS X 10\.4$", string:os )) security_hole(0);
