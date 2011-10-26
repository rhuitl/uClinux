#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#

desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is prone to arbitrary
code execution. 

Description :

The remote host is running WebGUI, a content management system from
Plain Black Software. 

The installed version of WebGUI on the remote host fails to sanitize
user-supplied input via the 'class' variable to various sources before
using it to run commands.  By leveraging this flaw, an attacker may be
able to execute arbitrary commands on the remote host within the
context of the affected web server userid. 

See also : 

http://www.plainblack.com/getwebgui/advisories/security-exploit-patch-for-6.3-and-above

Solution : 

Upgrade to WebGUI 6.7.6 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

if (description) {
script_id(20014);
script_version("$Revision: 1.3 $");
script_cve_id("CVE-2005-4694");
script_bugtraq_id(15083);
if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"19933");
}

name["english"] = "WebGUI < 6.7.6 arbitrary command execution";
script_name(english:name["english"]);

script_description(english:desc["english"]);

summary["english"] = "Checks for arbitrary remote command execution in WebGUI < 6.7.6";
script_summary(english:summary["english"]);

script_category(ACT_GATHER_INFO);
script_family(english:"CGI abuses");

script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");

script_dependencies("http_version.nasl");
script_exclude_keys("Settings/disable_cgi_scanning");
script_require_ports("Services/www", 80);

exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


http_check_remote_code (
			check_request:"/index.pl/homels?func=add;class=WebGUI::Asset::Wobject::Article%3bprint%20%60id%60;",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			extra_check:'<meta name="generator" content="WebGUI 6',
			command:"id",
			description:desc["english"]
			);
