#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10422);
 script_bugtraq_id(1252);
 script_cve_id("CVE-2000-0446");
 script_version ("$Revision: 1.11 $");
 
 
 name["english"] = "MDBMS overflow";
 name["francais"] = "Overflow MDBMS";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
A beta version of the MDBMS database is running, and it's 
very likely that it is vulnerable to a buffer overflow
(that we did not test for though) which may give a root
shell to anyone.

Solution : disable this service if you do not use it or
filter incoming connections to ports 2223 and 2224

Risk factor : High";


 desc["francais"] = "
Une version beta de MDBMS tourne sur ce port, et il est
très probable que celle-ci soit vulnérable à un dépassement
de buffer permettant à n'importe qui de passer root.

Solution : désactivez ce service si vous ne l'utilisez pas
ou filtrez les connections vers les port 2223 et 2224";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks the remote MDBMS version";
 summary["francais"] = "Vérifie le numéro de version du MDBMS distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(2223, 2224);
 exit(0);
}


include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);

port = 2224;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc){
	port = 2223;
	if ( get_port_state(port) )
	 {
	 soc = open_sock_tcp(port);
	 if(!soc)exit(0);
	 }
	else exit(0);
	}

r = recv_line(socket:soc, length:1024);
close(soc);
if(ereg(pattern:"^.*MDBMS V0\..*", string:r))
{
security_hole(port);
}


