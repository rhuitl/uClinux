#
# (C) Tenable Network Security
#


if(description) {
  script_id(11816);
  script_version("$Revision: 1.7 $");

  name["english"] = "phpWebSite multiple flaws";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains several PHP scripts that are prone to 
multiple flaws.

Description : 

There are multiple flaws in the remote version of phpWebSite that may
allow an attacker to gain the control of the remote database, or to
disable this site entirely. 

See also : 

http://lists.grok.org.uk/pipermail/full-disclosure/2003-August/007827.html
http://phpwebsite.appstate.edu/index.php?module=announce&ANN_user_op=view&ANN_id=577

Solution : 

Upgrade to the latest version of this software

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection and more.";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 - 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("phpwebsite_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Check each installed instance, stopping if we find a vulnerability.
install = get_kb_item(string("www/", port, "/phpwebsite"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  req = http_get(item:dir + "/index.php?module=calendar&calendar[view]=day&year=2003%00-1&month=", port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if(buf == NULL)exit(0);

  if(egrep(pattern:".*select.*mod_calendar_events.*", string:buf)) {
    security_hole(port);
    exit(0);
  }
}
