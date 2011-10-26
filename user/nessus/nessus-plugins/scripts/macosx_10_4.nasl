#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18352);
 script_version ("$Revision: 1.2 $");
 script_bugtraq_id(13467);
 name["english"] = "Mac OS X < 10.4";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Mac OS X which is older than
version 10.4.

Versions older than 10.4 contain a security issue in the way they handle
the permissions of pseudo terminals. 

When an application uses a new pseudo terminal, it can not restrict its 
permissions to a safe mode. As a result, every created pseudo terminal
has permissions 0666 set, which allows a local attacker to sniff the session
of other users.

Solution : Upgrade to Mac OS X
See also : http://www.securityfocus.com/archive/1/397306
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of Mac OS X";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl", "mdns.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("mDNS/os");
if ( ! os ) exit(0);

if ( ereg(pattern:"Mac OS X 10\.[0-3]([^0-9]|$)", string:os )) security_warning(0);
