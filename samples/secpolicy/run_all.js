var WshShell = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");
var server_port = 7070;

var f, s, re, ss, r;
var ForReading = 1, ForWriting = 2;

var axis2c_home = WshShell.ExpandEnvironmentStrings("%AXIS2C_HOME%");
var client_repo = axis2c_home + "\\client_repo";

for (var i = 14; i <= 0; i++) {
    WScript.Echo("Scenario " + i + ":");    
    deploy(i);
    WScript.Echo("services.xml and policy.xml deployed");
    var http_server = WshShell.Exec(axis2c_home + "\\bin\\axis2_http_server.exe -p " + server_port + " -r " + axis2c_home);
    WScript.Sleep(3000);    		
    WScript.Echo("Started Axis2C simple HTTP server\n\n");    
    var client;
    if (i != 14) {
    	client = WshShell.Exec(axis2c_home + "\\bin\\samples\\rampart\\client\\sec_echo\\echo.exe http://localhost:9090/axis2/services/sec_echo/echoString " + client_repo);
    } else if (i == 14) {
	    client = WshShell.Exec(axis2c_home + "\\bin\\samples\\rampart\\client\\saml_echo\\echo.exe http://localhost:9090/axis2/services/sec_echo/echoString " + client_repo);
    }	
    s = client.StdOut.ReadAll();
    WScript.Echo(s);
    http_server.Terminate();
}

WScript.Echo("Scenario " + 20 + ":");
deploy(20);
deploy_20();
WScript.Echo("services.xml and policy.xml deployed");
var http_server = WshShell.Exec(axis2c_home + "\\bin\\axis2_http_server.exe -p " + server_port + " -r " + axis2c_home);
WScript.Sleep(3000);    		
WScript.Echo("Started Axis2C simple HTTP server\n\n");
var client = WshShell.Exec(axis2c_home + "\\bin\\samples\\rampart\\client\\issued_token\\echo.exe http://localhost:9090/axis2/services/sec_echo/echoString " + client_repo);
s = client.StdOut.ReadAll();
WScript.Echo(s);
http_server.Terminate();

function replace()   
{
    while (s.search(/AXIS2C_HOME/) != -1) {
        r = s.replace(/AXIS2C_HOME/, axis2c_home);
        s = r;
    }
    while (s.search(/libpwcb\.so/) != -1) {
        r = s.replace(/libpwcb\.so/, "pwcb.dll");
        s = r;
    }
    while (s.search(/librdflatfile\.so/) != -1) {
        r = s.replace(/librdflatfile\.so/, "rdflatfile.dll");
        s = r;
    }
}

function deploy(i)
{
    f = fso.OpenTextFile("scenario" + i + "\\client-policy.xml", ForReading);
    s = f.ReadAll();
    f.Close();

    f = fso.OpenTextFile(client_repo + "\\policy.xml", ForWriting, true);
    replace();
    f.write(s);
    f.close();

    // Deploy the servces.xml files
    f = fso.OpenTextFile("scenario" +  i + "\\services.xml", ForReading);
    s = f.ReadAll();
    f.Close();
     
    f = fso.OpenTextFile(axis2c_home + "\\services\\sec_echo\\services.xml", ForWriting, true);
    replace();
    f.write(s);
    f.close();
}

function deploy_20()
{
    f = fso.OpenTextFile("scenario" + 20 + "\\sts-client-policy.xml", ForReading);
    s = f.ReadAll();
    f.Close();
    f = fso.OpenTextFile(client_repo + "\\sts_policy.xml", ForWriting, true);
    replace();
    f.write(s);
    f.close();
    f = fso.OpenTextFile("scenario" +  20 + "\\sts-services.xml", ForReading);
    s = f.ReadAll();
    f.Close();
    f = fso.OpenTextFile(axis2c_home + "\\services\\saml_sts\\services.xml", ForWriting, true);
    replace();
    f.write(s);
    f.close();
}
