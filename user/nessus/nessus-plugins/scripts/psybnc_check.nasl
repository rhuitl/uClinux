if(description)
{
  script_id(14687);
  script_version ("$Revision: 1.2 $");

  name["english"] = "psyBNC Server Detection";
  script_name(english:name["english"]);

  desc["english"] = "
The remote host appears to be running psyBNC on this port.

psyBNC is an 'easy-to-use, multi-user, permanent IRC-Bouncer with many features. Some 
of its features include symmetric ciphering of talk and connections (Blowfish and IDEA),
the possibility of linking multiple bouncers to an internal network including a shared 
partyline, vhost- and relay support to connected bouncers and an extensive online help 
system.'

The presence of this service indicates a high possibility that your server has been 
compromised by a remote attacker.  The only sure fix is to reinstall from scratch.


See also :
  http://www.psybnc.info/about.html
 http://www.psychoid.net/start.html

Solution : Make sure the presence of this service is intended
Risk Factor : High";

  script_description(english:desc["english"]);
  summary["english"] = "Check for the presence of psyBNC.";
  script_summary(english:summary["english"]);
  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2004 Scott Shebby");

  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencies("find_service2.nasl");
  exit(0);
}

# The detection is in find_service2.nasl
port = get_kb_item("Services/psyBNC");
if ( port ) security_hole(port);
