#
# (C) Tenable Network Security
#

if(description)
{
  script_id(19948);
  script_cve_id("CVE-1999-0526");
  script_version ("$Revision: 1.3 $");

  name["english"] = "Open X11 Server";
  script_name(english:name["english"]);
  desc["english"] = "
Synopsis :

The remote X11 server accepts connections from anywhere.

Description :

The remote X11 server accepts connection from anywhere. An attacker
may connect to it to eavesdrop on the keyboard and mouse events of
a user on the remote host. It is even possible for an attacker to 
grab a screenshot of the remote host or to display arbitrary programs.

An attacker may exploit this flaw to obtain the username and password
of a user on the remote host.

Solution :

Restrict access to this port by using the 'xhost' command. 
If the X11 client/server facility is not used, disable TCP entirely.

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";




 script_description(english:desc["english"]);

 summary["english"] = "X11 determines if X11 is open";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("X.nasl");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 exit(0);
}



for ( i = 0 ; i < 10 ; i ++ )
{
 if ( get_kb_item("x11/" + int(i + 6000) + "/open") ) security_warning(i + 6000);
}
