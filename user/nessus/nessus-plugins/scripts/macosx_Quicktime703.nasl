#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20135);
 script_version ("1.0");
 script_bugtraq_id(15306, 15307, 15308, 15309);
 name["english"] = "Quicktime < 7.0.3";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote version of QuickTime may allow an attacker to execute arbitrary
code on the remote host.

Description :

The remote Mac OS X host is running a version of Quicktime 7 which is older
than Quicktime 7.0.3.

The remote version of this software is vulnerable to various buffer overflows 
which may allow an attacker to execute arbitrary code on the remote host by
sending a malformed file to a victim and have him open it using QuickTime 
player.

Solution : 

Install Quicktime 7.0.3

See also : 

http://docs.info.apple.com/article.html?artnum=302772

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Quicktime 7.0.3";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("macosx_Quicktime652.nasl");
 script_require_keys("MacOSX/QuickTime/Version");
 exit(0);
}

ver = get_kb_item("MacOSX/QuickTime/Version");
if (! ver ) exit(0);

version = split(ver, sep:'.', keep:FALSE);
if ( int(version[0]) == 7 && int(version[1]) == 0 && int(version[2]) < 3 ) security_warning(0);
