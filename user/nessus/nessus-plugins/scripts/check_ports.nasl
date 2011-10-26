#
# This script was written by Michel Arboi <arboi@alussinan.org> 
#
# GPL, blah blah blah
# See the Nessus Scripts License for details
#
# Services known to crash or freeze on a port scan:
#
# ClearCase (TCP/371)
# NetBackup
# 
################
# References
################
#
# From: marek.rouchal@infineon.com
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org, 
#   submissions@packetstormsecurity.org
# CC: rheinold@rational.com, buggy@segmentationfault.de, 
#    Thorsten.Delbrouck@guardeonic.com, manfred.korger@infineon.com
# Date: Fri, 22 Nov 2002 10:30:11 +0100
# Subject: ClearCase DoS vulnerabilty
#

if(description)
{
 script_id(10919);
 script_version ("$Revision: 1.20 $");

 name["english"] = "Check open ports";
 name["francais"] = "Vérifie les ports ouverts";
 
 script_name(english:name["english"],
            francais:name["francais"]);
 
 desc["english"] = "
This plugin checks if the port scanners did not kill a service.

Risk factor : None";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check if ports are still open";
 summary["francais"] = "Vérifie si les ports sont toujours ouverts";
 script_summary(english:summary["english"],
               francais:summary["francais"]);
 
 script_category(ACT_END);


 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("find_service.nes");
 exit(0);
}

#


ports = get_kb_list("Ports/tcp/*");
if(isnull(ports))exit(0);

at_least_one = 0;
number_of_ports = 0;
report = make_list();
timeouts = 0;

foreach port (keys(ports))
{
   number_of_ports ++;
   port = int(port - "Ports/tcp/");
   to = get_kb_item("/tmp/ConnectTimeout/TCP/"+port);
   if (to)
     timeouts++;
   else
   {
   s = open_sock_tcp(port, transport:ENCAPS_IP);
   if (! s)
    {
    report[port] = 
'This port was detected as being open by a port scanner but is now closed.\n' +
'This service might have been crashed by a port scanner or by a plugin\n';
    }
   else
    {
    close(s);
    at_least_one ++;
    }
   }
}


if( number_of_ports == 0 )exit(0);

if(at_least_one > 0 || number_of_ports == 1)
{
 foreach port (keys(report))
 {
  security_note(port:port, data:report[port]);
 }
}
else
{
 text = "
Nessus cannot reach any of the previously open ports of the remote
host at the end of its scan.
";
 if (timeouts > 0)
 {
   text = "
** ";
   if (timeouts == number_of_ports)
    text += "All ports";
   else
    text = strcat(text, "Some of the ports (", timeouts, "/", number_of_ports, ")");
   text += " were skipped by this check because some
** scripts could not connect to them before the defined timeout
";
 }
 text += "
This might be an availability problem related which might be
due to the following reasons :

- The remote host is now down, either because a user turned it
off during the scan";

 if(safe_checks() == 0) text += 
" or a selected denial of service was effective against 
this host";

text += '

- A network outage has been experienced during the scan, and the remote 
network cannot be reached from the Nessus server any more

- This Nessus server has been blacklisted by the system administrator
or by automatic intrusion detection/prevention systems which have detected the 
vulnerability assessment.


In any case, the audit of the remote host might be incomplete and may need to
be done again
';

 security_note(port:0, data:text); 
}
