#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18062);
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(13203, 13202, 13207, 13225, 13223, 13222, 13221);
 script_cve_id("CVE-2005-0970", "CVE-2005-0971", "CVE-2005-0972", "CVE-2005-0976");
 name["english"] = "Mac OS X < 10.3.9";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Mac OS X 10.3 which is older than
version 10.3.9.

Mac OS X 10.3.9 contains several security fixes for :

- Safari : a remote local zone script execution vulnerability has been fixed
- kernel : multiple local privilege escalation vulnerabilities have been fixed

Solution : http://docs.info.apple.com/article.html?artnum=301327
Risk factor : Medium";


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

if ( ereg(pattern:"Mac OS X 10\.3\.[0-8]([^0-9]|$)", string:os )) security_warning(0);
