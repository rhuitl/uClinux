#TRUSTED 24ea45a3fa73c62e0e91e0d0d984aa6393259c5408e58ce7af83a4dd99d54458bc243d5c5546b996f5cc9c61217be1788d4f33cd590c2edf46723bc92ff13099df53ae351590a2d791f3fe1c8a53517cc11d0aa4ea41e6d6562eeab584df4e99d14fc25d016a5ac477506cad22b3886ace0ec88f41f9a12a5cb2ec1a0bbaa74c6dec9210c231d50b9a8d8ddd84aa0c992b15024ed6a0ae065793f61df81177854e9a63237ef38b32093411972d1da3fcba9eafc8ddde1650f0fd4956b6189d0ce9c5ada38153cc890ebceca0ac8aa1ac05f7648185263c1c91ff3be88cb7525073baf26f6161ac904866b64b78d6aedc5fb7b54306847c7e282cd8df0c34b36eb2866afa710ed4bd245ef55f38c4e3053c803e021696810b9033386d289e6366d73e19c7848c1a3e508f1f6c542a4ebbb773f42508ab2aa22b573f7113e756c979e601d18e392398e71ec84398ed0a206416ec0e8d60612a31781d97ae3fea1025861d9a9cbc9299e9fa13ab8c73556a6d279557ee96726613981428b8e9f81afb83127b6e112800c60903622d3cd24484debca93de045e5157139e44dca3fb197aab45961edee5480ba356d00890d5b3a13ac265b752114d7dd26ec1f14565a881d1fb410fd66e804548c2d77d965e202921fd0a724847664e03ec110d33f29184de0b4262d5d545d581ea08795b79bc9308ac149d17b5abd145a2919c18a44
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if ( ! defined_func("script_get_preference_file_location")) exit(0);
if ( ! find_in_path("hydra") ) exit(0);


if(description)
{
 script_id(15884);
 script_version ("1.2");
 name["english"] = "Hydra: SMB";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find SMB accounts & passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force SMB authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK); # Because of accounts autolock
 script_timeout(0);
 script_add_preference(name: "Check local / domain accounts", 
	value: "Local accounts; Domain Accounts; Either", type: "radio");
 script_add_preference(name: "Interpret passwords as NTLM hashes", 
	value: "no", type: "checkbox");

 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports(139,445);
 script_dependencies("hydra_options.nasl", "find_service.nes", "doublecheck_std_services.nasl");
 exit(0);
}

#

throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("SMB/transport"); port = int(port);
if (! port) port = 445;
if (! get_port_state(port)) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
argv[i++] = "-L"; argv[i++] = logins;
argv[i++] = "-P"; argv[i++] = passwd;
s = "";
if (empty) s = "n";
if (login_pass) s+= "s";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}
if (exit_asap) argv[i++] = "-f";
if (tr >= ENCAPS_SSLv2) argv[i++] = "-S";

if (timeout > 0)
{
  argv[i++] = "-w";
  argv[i++] = timeout;
}
if (tasks > 0)
{
  argv[i++] = "-t";
  argv[i++] = tasks;
}

argv[i++] = get_host_ip();
argv[i++] = "smbnt";	# what's "smb"?

opt = "";
p = script_get_preference("Check local / domain accounts");
if ("Local" >< p) opt = "L";
else if ("Domain" >< p) opt = "D";
else opt = "B";

p = script_get_preference("Interpret passwords as NTLM hashes");
if ("yes" >< p) opt += "H";
argv[i++] = opt;

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'username: ', l, '\tpassword: ', p, '\n');
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following SMB accounts:\n' + report);
