#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Alexander Antipov <antipov SecurityLab ru> - MAxpatrol Security
#
#  This script is released under the GNU GPL v2

if(description)
{
 script_id(15451);
 script_cve_id("CVE-2004-1588", "CVE-2004-1589");
 script_bugtraq_id(11361);
 script_version ("$Revision: 1.5 $");
 name["english"] = "GoSmart message board multiple flaws";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running GoSmart message board, a bulletin board 
manager written in ASP.


The remote version of this software contains multiple flaws, due o
to a failure of the application to properly sanitize user-supplied input.

It is also affected by a cross-site scripting vulnerability. 
As a result of this vulnerability, it is possible for a remote attacker
to create a malicious link containing script code that will be executed 
in the browser of an unsuspecting user when followed. 

Furthermore, this version is vulnerable to SQL injection flaws that
let an attacker inject arbitrary SQL commands.

Solution : Upgrade to the newest version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks GoSmart message board flaws";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak",
		francais:"Ce script est Copyright (C) 2004 David Maciejak");
		
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!get_port_state(port))exit(0);
if ( ! can_host_asp(port:port) ) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

foreach dir (cgi_dirs())
{
 req = string(dir, "/messageboard/Forum.asp?QuestionNumber=1&Find=1&Category=%22%3E%3Cscript%3Efoo%3C%2Fscript%3E%3C%22");
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if (egrep(pattern:"<script>foo</script>", string:r))
 {
       security_warning(port);
       exit(0);
 }
}
