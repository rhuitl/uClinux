#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11633);
 script_version ("$Revision: 1.3 $");

 name["english"] = "lovgate virus is installed";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be infected with the 'lovgate' virus
which opens a command prompt on this port.

Solution : See http://securityresponse.symantec.com/avcenter/venc/data/w32.hllw.lovgate.c@mm.html
Risk : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of Luvgate";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
# script_dependencie("find_service.nes");
 script_require_ports(10168, 1192, 20168);
 exit(0);
}

#
# The script code starts here
#

ports = make_list(10168, 1192, 20168);
foreach port (ports)
{
 r = get_kb_item("FindService/tcp/" + port + "/spontaneous");
 if(r)
   {
    if("Microsoft Windows" >< r &&
       "(C) Copyright 1985-" >< r &&
       "Microsoft Corp." >< r){security_hole(port); exit(0);}
   }
}
