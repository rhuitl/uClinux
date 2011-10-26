#
# (C) Tenable Network Security

if(description)
{
 script_id(11694);
 script_bugtraq_id(7740, 7745, 7747);
 script_version("$Revision: 1.6 $");
 name["english"] = "P-Synch multiple issues";
 script_name(english:name["english"]);

 desc["english"] = "
The remote web server is running P-Synch, a password management
system running over HTTP.

There is a flaw in the CGIs nph-psa.exe and nph-psf.exe which
may allow an attacker to make this host include remote
files, disclose the path to the p-synch installation or
produce arbitrary HTML code (cross-site scripting).

Solution : Upgrade to the latest version of P-Synch
Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "P-Synch issues";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "httpver.nasl", "no404.nasl", "webmirror.nasl", "cross_site_scripting.nasl");
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


if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

dirs = make_list("/psynch", cgi_dirs());
foreach dir (dirs)
{
 foreach cgi (make_list("nph-psa.exe", "nph-psf.exe"))
 {
 req = http_get(item:dir + '/' + cgi + '?css="><script>test</script>', port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
    "<script>test</script>" >< res) { security_warning(port); exit(0); }
 }
}

