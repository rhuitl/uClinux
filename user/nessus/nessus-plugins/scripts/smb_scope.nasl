

if(description)
{
 script_id(10917);
 script_version ("$Revision: 1.1 $");

 name["english"] = "SMB Scope";

 
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin configures Nessus so that
it knows if it should query local information
on each host or information pertaining to
the domain (ie: requests will be forwarded
to the PDC).

If you test a single workstation, you
want information about the domain. If
you test the whole network, including
the PDC, you won't want redundant information.

See the plugins preferences panel for details.


Risk factor : None";


 script_description(english:desc["english"]);
 
 summary["english"] = "SMB scope options";
 summary["francais"] = "SMB scope options";
 script_summary(english:summary["english"],
               francais:summary["francais"]);
 
 script_category(ACT_SETTINGS);
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Settings";
 family["francais"] = "Configuration";
 script_family(english:family["english"], francais:family["francais"]);
 
 script_add_preference(name:"Request information about the domain",
 	type:"checkbox", value:"yes");
 exit(0);
}

x =  script_get_preference("Request information about the domain");

if((x == "yes"))
{
 set_kb_item(name:"SMB/test_domain", value:TRUE);
}
