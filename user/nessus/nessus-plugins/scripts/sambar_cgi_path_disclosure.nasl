#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# References:
# From: <gregory.lebras@security-corporation.com>
# To: vulnwatch@vulnwatch.org
# Date: Thu, 27 Mar 2003 15:25:40 +0100
# Subject: [SCSA-012] Multiple vulnerabilities in Sambar Server
#
# Vulnerables:
# Sambar WebServer v5.3 and below 
#

if(description)
{
 script_version ("$Revision: 1.5 $");
 script_id(11775);
 script_name(english:"Sambar CGIs path disclosure");
 
 desc["english"] = "
environ.pl or testcgi.exe is installed. Those CGIs
reveal the installation directory and some other information 
that could help a cracker.

Solution : remove them

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Some CGIs reveal the web server installation directory";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencies("find_service.nes", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/sambar");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

if (http_is_dead(port: port)) exit(0);

files = make_list("cgitest.exe", "environ.pl");
dirs = cgi_dirs();

foreach dir (dirs)
{
  foreach fil (files)
  {
    soc = http_open_socket(port);
    if (! soc) exit(0);
    req = http_get(port: port, item: strcat(dir, "/", fil));
    r = http_keepalive_send_recv(port:port, data: req);
    p = strcat("SCRIPT_FILENAME:*", fil);
    if (r && (match(string: r, pattern: p) || r =~ 'DOCUMENT_ROOT:[ \t]*[A-Z]\\\\'))
    {
      security_warning(port);
      exit(0);
    }
  }
}

