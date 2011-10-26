#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20911);
 script_version ("$Revision: 1.3 $");
 script_bugtraq_id(16654);
 script_cve_id("CVE-2006-0382");
 name["english"] = "Mac OS X < 10.4.5";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote host is missing a Mac OS X update which fixes a security
issue.

Description :

The remote host is running a version of Mac OS X 10.4 which is older than
version 10.4.5.

Mac OS X 10.4.5 contains several security fixes for a local denial of
service vulnerability. A malicious local user may trigger the vulnerability
by invoking an undocumented system call.


Solution : 

Upgrade to Mac OS X 10.4.5 :
http://www.apple.com/support/downloads/macosxupdate1045.html
http://www.apple.com/support/downloads/macosxserver1045.html

See also :

http://docs.info.apple.com/article.html?artnum=61798

Risk factor :

Low / CVSS Base Score : 1.6
(AV:L/AC:L/Au:NR/C:N/I:N/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of Mac OS X";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl","mdns.nasl");
 #script_require_keys("Host/MacOSX/packages");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("mDNS/os");
if ( ! os ) exit(0);

if ( ereg(pattern:"Mac OS X 10\.4($|\.[1-4]([^0-9]|$))", string:os )) security_note(0);
