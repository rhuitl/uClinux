#
# This script was written by Josh Zlatin-Amishav <josh at ramat dot cc>
#
# This script is released under the GNU GPLv2


if(description)
{
 script_id(19679);
 script_cve_id("CVE-2005-2595");
 script_bugtraq_id(14573);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"18772");
 }
 script_version ("$Revision: 1.4 $");

 name["english"] = "XSS vulnerability in Dada Mail";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running Dada Mail, a free, e-mail list management
system written in Perl. 

According to its banner, the remote version of this software does not
properly validate user written content before submitting that data to
the archiving system.  A malicious user could embed arbitrary
javascript in archived messages to later be executed in a user's
browser within the context of the affected web site. 

See also : http://sourceforge.net/project/shownotes.php?release_id=349531 
Solution : Upgrade to version 2.10 alpha 1 or higher.
Risk factor : Medium";

 script_description(english:desc["english"]);

 summary["english"] = "Checks Dada Mail version";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"Copyright (C) 2005 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (thorough_tests) dirs = make_list("/cgi-bin/dada", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 req = http_get(
   item:string(
     dir, "/mail.cgi"
   ), 
   port:port
 );
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 # versions 2.9.x are vulnerable
 if(egrep(pattern:"Powered by.*Dada Mail 2\.9", string:res))
 {
        security_warning(port);
        exit(0);
 }
}
