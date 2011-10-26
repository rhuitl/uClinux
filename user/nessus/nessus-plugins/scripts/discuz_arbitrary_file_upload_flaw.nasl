#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: Jeremy Bae at STG Security
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(19751);
 script_cve_id("CVE-2005-2614");
 script_bugtraq_id(14564);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "Discuz! <= 4.0.0 rc4 Arbitrary File Upload Flaw";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Discuz!, a popular web application forum in
China. 

According to its version, the installation of Discuz! on the remote host
fails to properly check for multiple extensions in uploaded files.  An
attacker may be able to exploit this issue to execute arbitrary commands
on the remote host subject to the privileges of the web server user id,
typically nobody. 

See also : http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0440.html
Solution : Upgrade to the latest version of this software.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks Discuz! version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if ( !get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/index.php"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if (("powered by Discuz!</title>" >< r) && egrep(pattern:'<meta name="description" content=.+Powered by Discuz! Board ([1-3]|4\\.0\\.0RC[0-4])', string:r))
 {
   security_warning(port);
   exit(0);
 }
}

if (thorough_tests) dirs = make_list("/discuz", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 check(loc:dir);
}
