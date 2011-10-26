#
# This script was written by Jøséph Mlødzianøwski <joseph@rapter.net>
# 
# 

if(description)
{

 script_id(11881);
 script_version ("$Revision: 1.5 $");
# script_cve_id("CVE-2003-00002");
 name["english"] = "Wollf backdoor detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
This host appears to be running Wollf on this port. Wollf Can be used as a 
Backdoor which allows an intruder gain remote access to files on your computer. 
If you did not install this program for remote management then this host may 
be compromised.

An attacker may use it to steal your passwords, or redirect
ports on your system to launch other attacks

Solution : see www.rapter.net/jm4.htm for details on removal
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of Wollf";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2003 J.Mlødzianøwski");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("find_service2.nasl");
 exit(0);
}


#
# The code starts here:
#

port = get_kb_item("Services/wollf");
if ( port ) security_hole(port);

