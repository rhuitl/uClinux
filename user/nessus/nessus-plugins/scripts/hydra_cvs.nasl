#TRUSTED 93e66b369c208254bdfb402ad3a078bcfd7ceee7ea4ffeed5e900be164a549296672b344cb998529318773630d9188cc95ae10c9a5cafe6928f3560b85e87cae02e51ef0622c67eefafcf75731e0c7428621fca342491597864b7ace8e72d430982ef1c14b235ee21a51c80e6d7e45dfa9f49b5740a28f5477728edae8bd36f6741d90adb8a89078c0340a10759c9590720d02a91388cd0d6a923e794857df8f9870865990173de81909d5bd81c517f7a979f7a971f59207d1ce9ef874acc9c480dd33ddfca0946348bbd251bc2c0cb032630562e56b625c2cf28dacc250d1deffe7c773319e35201acca41f5fb1bac2d4102bfd727226f2c38e88873990ea6a4d98133ef9aabb24d0a161fb007644c88644abb60c6e2a79edc70a437daca460c9646d7205ce8c26c52b7930e073ada8959c61629b86d6daee72cb04cfec5011df04cae21e0e335af3f27eea3a55220e102f17a956285aae815ba0a9007d931ef803a44922403d3f16ced289bfa10c51336922b7fe51046a51718dbf3a8547ce5dadbb440138d050ac96a1635156707c5a43c34476be5be8d71ca0366105a8e739a750f2b4965c6e0ea05113a63167df928c697795993cf234678889983bf9495eaefe7f5e0842f2ed01711978ea363c2391732b7dcc46edc91cb43180756a1c759f4838cb866edb279beae742c8a41b55b7f257f536f3dffa41d44341dcf3b9
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(15871);
 script_version ("1.2");
 name["english"] = "Hydra: CVS";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find CVS accounts & passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force CVS authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_timeout(0);
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("hydra_options.nasl", "find_service.nes", "cvs_detect.nasl");
 exit(0);
}

#

throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/cvspserver");
if (! port) port = 2401;
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
argv[i++] = "cvs";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'login: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/cvs/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following CVS accounts:\n' + report);
