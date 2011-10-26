#
# Copyright (C) 2004 Tenable Network Security
#

if(description)
{
 script_id(12219);
 script_version ("$Revision: 1.8 $");
 name["english"] = "Sasser Virus Detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote hos is infected by a virus.

Description :

The Sasser worm is infecting this host.  Specifically,
a backdoored command server may be listening on port 9995 or 9996
and an ftp server (used to load malicious code) is listening on port 
5554 or 1023.  There is every indication that the host is currently 
scanning and infecting other systems.  

See also : 

http://www.lurhq.com/sasser.html

Solution: 

- Use an Anti-Virus package to remove it.
- See http://www.microsoft.com/technet/security/bulletin/ms04-011.asp

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Sasser Virus Detection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(
  english:"This script is Copyright (C) 2004 Tenable Network Security",
  francais:"Ce script est copyright (C) 2004 Tenable Network Security");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(5554);
 exit(0);
}

# start script

include("ftp_func.inc");
login = "anonymous";
pass  = "bin";

# there really is no telling how many Sasser variants there will be :<
ports[0] =  5554;           
ports[1] =  1023;

foreach port ( ports)
{
 if ( get_port_state(port) )
   {
        soc = open_sock_tcp(port);
        if (soc) 
        {
            if(ftp_authenticate(socket:soc, user:login, pass:pass)) security_hole(port);
	    close(soc);
        }
    }
}





