# The script was written by Michel Arboi <arboi@alussinan.org>
# GNU Public Licence
#
# References:
#
# From:Stefan.Bagdohn@guardeonic.com
# To: bugtraq@securityfocus.com
# Subject: Advisory: TCP-Connection risk in DB4Web 
# Date: Tue, 17 Sep 2002 14:44:17 +0200
#

if(description)
{
 script_id(11180);
 script_version ("$Revision: 1.6 $");
  
 name["english"] = "DB4Web TCP relay";
 script_name(english:name["english"]);
 
 desc["english"] = "
DB4Web debug page allows anybody to scan other machines.
You may be held for responsible.

Solution : Replace the debug page with a non-verbose error page.

Risk factor : High";


 desc["francais"] = "
La page de debug de DB4Web permet à n'importe qui
de scanner d'autres machines.
Votre responsabilité pourrait être engagée.

Solution : Remplacez la page de debug par une page d'erreur moins verbeuse 

Facteur de risque : Elevé";




 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "DB4Web debug page allow bounce scan";
 summary["francais"] = "La page de debug de DB4Web permet de scanner par rebond";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");	

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 	

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);


# testhost = "nosuchwww.example.com";
testhost = this_host_name();

r = http_get(port: port, item: string("/DB4Web/", testhost, ":23/foo"));
c = http_keepalive_send_recv(port:port, data:r);

if ((("connect() ok" >< c) || ("connect() failed:" >< c)) &&
    ("callmethodbinary_2 failed" >< c))
  security_hole(port);
