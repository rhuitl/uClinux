#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: ZetaLabs, Zone-H Laboratories
#
#  This script is released under the GNU GPL v2
#

 desc = "
The script i-mall.cgi is installed.  Some versions of this script are
vulnerable to remote command exacution flaw, due to insuficient user
input sanitization.  A malicious user can pass arbitrary shell commands
on the remote server through this script. 

Solution : None at this time.
Risk factor : High";


if(description)
{
 script_id(15750);
 script_cve_id("CVE-2004-2275");
 script_bugtraq_id(10626);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"7461");
 
 script_version ("$Revision: 1.5 $");
 name["english"] = "i-mall.cgi";
 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Checks for the presence of i-mall.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here
include("http_func.inc");
include("http_keepalive.inc");
include('global_settings.inc');


if ( thorough_tests )
{
 extra_list = make_list ("/i-mall");
}
else
  extra_list = NULL;

http_check_remote_code (
			extra_dirs: extra_list,
			check_request:"/i-mall.cgi?p=|id|",
			check_result:"uid=[0-9]+.* gid=[0-9]+.*",
			command:"id",
			description:desc
			);
