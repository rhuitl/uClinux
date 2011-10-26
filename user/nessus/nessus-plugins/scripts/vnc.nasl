#
# This script was written by Patrick Naubert
# This is version 2.0 of this script.
#
# Modified by Georges Dagousset <georges.dagousset@alert4web.com> :
#	- warning with the version
#	- detection of other version
#	- default port for single test
#
# See the Nessus Scripts License for details
#

 desc["english"] = "
Synopsis :

The remote host is running a remote display software (VNC).

Description :

The remote server is running VNC, a software which permits a console
to be displayed remotely.  This allows users to control the host
remotely. 

Solution : 

Make sure the use of this software is done in accordance with your
corporate security policy and filter incoming traffic to this port. 

Risk factor : 

None";

if(description)
{
 script_id(10342);
 script_version ("$Revision: 1.15 $");
# script_cve_id("CVE-MAP-NOMATCH");
 name["english"] = "Check for VNC";
 name["francais"] = "Check for VNC";
 script_name(english:name["english"], francais:name["francais"]);
 



 desc["francais"] = "
Le serveur distant fait tourner VNC.
VNC permet d'acceder la console a distance.

Solution: Protégez l'accès à VNC grace à un firewall,
ou arretez le service VNC si il n'est pas desire.

Facteur de risque : Moyen";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for VNC";
 summary["francais"] = "Vérifie la présence de VNC";
 
 script_summary(english:summary["english"],
francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Patrick Naubert",
                francais:"Ce script est Copyright (C) 2000 Patrick Naubert");
 script_family(english: "Service detection");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/vnc", 5900, 5901, 5902);
 exit(0);
}

#
# The script code starts here
#

function probe(port)
{
 # if (! get_port_state(port)) return 0;
 r = get_kb_item("FindService/tcp/" + port + "/spontaneous");
 if ( ! r ) return 0;
 version = egrep(pattern:"^RFB 00[0-9]\.00[0-9]",string:r);
 if(version)
   {
      report = desc["english"] + '\n\nPlugin output :\nThe version of the VNC protocol is : ' + version;
      security_note(port:port, data:report);
   }
}

port = get_kb_item("Services/vnc");
if(port)probe(port:port);
else
{
 for (port=5900; port <= 5902; port = port+1) {
  probe(port:port);
 }
}
