#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

The remote web server contains a bug tracking application written in
PHP. 

Description :

This script detects whether the remote host is running Mantis and
extracts its version number and location if found. 

Mantis is an open-source bug tracking application written in PHP and
with a MySQL back-end. 

See also :

http://www.mantisbt.org/

Risk factor : 

None";


if(description)
{
 script_id(11652);
 script_version ("$Revision: 1.8 $");
 

 name["english"] = "Mantis Detection";
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of Mantis";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);


# Search for Mantis.
if (thorough_tests) dirs = make_list("/bugs", "/mantis", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  req = http_get(item:string(dir, "/login_page.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if( res == NULL ) exit(0);

  res = egrep(pattern:"(http://mantisbt\.sourceforge\.net|http://www\.mantisbt\.org).*Mantis [0-9]", string:res, icase:TRUE);
  if( res ) {
    ver = ereg_replace(pattern:".*Mantis ([0-9][^ <]*).*", string:res, replace:"\1", icase:TRUE);
    if (dir == "") dir = "/";

    set_kb_item(
      name:string("www/", port, "/mantis"),
      value:string(ver, " under ", dir)
    );
	      
    info = string("Mantis ", ver, " was detected on the remote host under\nthe path ", dir, ".");
    report = ereg_replace(
      string:desc["english"],
      pattern:"This script[^\.]+\.", 
      replace:info
    );
    security_note(port:port, data:report);

    exit(0);     
  }
} 
