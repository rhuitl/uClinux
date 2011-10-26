#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20113);
 script_version ("$Revision: 1.3 $");
 script_bugtraq_id(15252);
 name["english"] = "Mac OS X < 10.4.3";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote host is missing a Mac OS X update which fixes security
issues.

Description :

The remote host is running a version of Mac OS X 10.4 which is older than
version 10.4.3.

Mac OS X 10.4.3 contains several security fixes for :

- Finder
- Sofware Update
- memberd
- KeyChain
- Kernel

Solution : 

Upgrade to Mac OS X 10.4.3 :
http://www.apple.com/support/downloads/macosxupdate1043.html
http://www.apple.com/support/downloads/macosxserver1043.html

See also :

http://docs.info.apple.com/article.html?artnum=61798

Risk factor :

Low / CVSS Base Score : 2 
(AV:L/AC:L/Au:R/C:P/A:N/I:P/B:N)";


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

if ( ereg(pattern:"Mac OS X 10\.4($|\.[12]([^0-9]|$))", string:os )) security_note(0);
