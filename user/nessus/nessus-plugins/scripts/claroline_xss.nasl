#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16318);
 script_bugtraq_id(12449);
 
 script_version ("$Revision: 1.3 $");
 name["english"] = "Claroline XSS";
 script_name(english:name["english"]);
 
 desc["english"] =  "
The remote host is running Claroline, a web-based collaboration tool
written in PHP.

The remote version of this software is vulnerable to several cross
site scripting attacks in the file 'add_course.php'.

With a specially crafted URL, an attacker may use the remote to
perform a cross site scripting attack against a user.

Solution : Upgrade to the latest version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if Claroline is vulnerable to a XSS attack";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);

 script_dependencie("claroline_detect.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(get_port_state(port))
{
  # Test an install.
  install = get_kb_item(string("www/", port, "/claroline"));
  if (isnull(install)) exit(0);
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    dir = matches[2];

    buf = http_get(item:dir + "/add_course.php?intitule=<script>foo<script>", port:port);
    r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
    if( r == NULL )exit(0);
    if( "/create_course/add_course.php?intitule=<script>foo</script>>" >< r )
      security_warning(port);
   }
}
