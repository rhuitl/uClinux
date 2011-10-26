#
# This script is Copyright (C) 2004 Tenable Network Security
#

if(description)
{
 script_id(15703);
 script_cve_id("CVE-2004-2612");
 script_bugtraq_id(11650);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"12144");
 }
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "BNC IRC Server Authentication Bypass Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of BNC, an IRC proxy,
which is vulnerable to an authentication bypass vulnerability.
An attacker may use this issue to use the remote IRC proxy
server.

Nessus was able to log in with a random password.

Solution : None at this time
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Check BNC authentication bypass";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);

 exit(0);
}

pwd = string("Nessus", rand());
nick = "nessus";
user = "nessus";


#most common bnc ports 6667,6669,8080

ports = make_list (6667, 6669, 8080);

foreach port (ports)
{
   if(get_port_state(port))
   {

    soc = open_sock_tcp(port);
    if (soc)
    {

     req = 'user nessus nessus nessus nessus\nnick nessus ~\n';
     send(socket: soc, data: req);

     r = recv(socket:soc, length:4096);
     if (r)
     {

       if ("NOTICE AUTH :You need to say /quote PASS <password>" >!< r) exit(0);
       {
         req = string ('pass ', pwd, '\n');
         send (socket:soc, data:req);

         r = recv(socket:soc, length:4096);
         if ((r) && ("NOTICE AUTH :Welcome to BNC" >< r))
         { 
          security_hole (port:port);
          exit(0);
         }
       }
     }
   close (soc);
  }
 }
}
