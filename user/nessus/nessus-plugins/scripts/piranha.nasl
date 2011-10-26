#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10381);
 script_bugtraq_id(1148);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0248");
 name["english"] = "Piranha's RH6.2 default password";
 name["francais"] = "Mot de passe par défaut de pirhana sur RedHat 6.2";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The 'piranha' package is installed on the remote host.
This package, as it is distributed with Linux RedHat 6.2,
comes with the login/password combination 'piranha/q'
(or piranha/piranha)

An attacker may use it to reconfigure your Linux Virtual Servers
(LVS).

Solution : upgrade the packages piranha-gui, piranha and piranha-docs to
           version 0.4.13

Risk factor : High";


 desc["francais"] = "
Le package 'piranha' est installé sur l'hote distant.
Ce package, tel qu'il est fourni avec la RedHat 6.2, est livré
avec la combinaison login/mot de passe par défaut 'piranha/q'
(ou 'piranha/piranha)

Un pirate peut l'utiliser pour reconfigurer vos serveurs virtuels
linux (LVS).

Solution : upgradez les packages piranha-gui, piranha et piranha-docs
           en la version 0.4.13

Facteur de risque : Elevé";	   


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "logs into the remote piranha subsystem";
 summary["francais"] = "se log dans le sysème piranha distant";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

function test_hole(auth, port)
{
 req = http_get(item:"/piranha/secure/control.php3?", port:port);
 req = req - string("\r\n\r\n");
 req = string(req, "\r\nAuthorization: Basic ", auth, "\r\n\r\n");
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 if("Piranha (Control/Monitoring)" >< r)
    {
      security_hole(port);
      exit(0);
    }
}



port = get_http_port(default:80);


if(get_port_state(port))
{
    if ( ! can_host_php(port:port) ) exit(0);
    test_hole(auth:"cGlyYW5oYTpx", port:port);
    test_hole(auth:"cGlyYW5oYTpwaXJhbmhh", port:port);
}
   

