#
# (C) Tenable Network Security
#

desc = "
The remote host is running JamMail, a web mail script written in
perl.

The remote version of this software is prone to a remote command
execution vulnerability. 

An attacker may exploit this vulnerability to execute commands on
the remote host by adding special parameters to jammail.pl script.

Solution : None at this time
Risk factor : High";


if(description)
{
 script_id(18477);
 script_cve_id("CVE-2005-1959");
 script_bugtraq_id(13937);
 script_version("$Revision: 1.4 $");

 name["english"] = "JamMail Jammail.pl Remote Arbitrary Command Execution Vulnerability";

 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Determines the presence of Jammail.pl remote command execution";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"CGI abuses");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include('global_settings.inc');


if ( thorough_tests )
{
 extra_list = make_list ("/mail", "/jammail", "/cgi-bin/jammail");
}
else
  extra_list = NULL;

http_check_remote_code (
			extra_dirs: extra_list,
			check_request:"/jammail.pl?job=showoldmail&mail=|id|",
			extra_check:"<td width=80% height=16>uid=[0-9].* gid=[0-9].*",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);
