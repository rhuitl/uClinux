#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18369);
 script_bugtraq_id(13771);
 script_version ("$Revision: 1.2 $");
 name["english"] = "Keynote < 2.0.2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host contains a version of Keynote 2 which is older than 2.0.2.

Keynote 2.0 and 2.0.1 contain a security issue which may allow an attacker to
send a rogue keynote file containing malformed URI links in it, which may
read and upload arbitrary files to an arbitrary location.

Solution : Upgrade to Keynote 2.0.2
See also : http://docs.info.apple.com/article.html?artnum=301713
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Keynote 2.0.2";
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

if ( egrep(pattern:"^Keynote 2\.pkg", string:packages) &&
     !egrep(pattern:"^Keynote2\.0\.([2-9]|[1-9][0-9])\.pkg", string:packages) &&
     !egrep(pattern:"^Keynote2\.[1-9]+\.", string:packages) )
		security_hole();
