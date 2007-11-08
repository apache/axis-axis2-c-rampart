The scenarios available here can be deployed using deploy.sh

Simply give the scenario name as an argument to the script.

E.g. %sh deploy.sh scenario1 
(Windows users please use the "win_deploy.bat")

Make sure you have run the "deploy_client_repo.sh".
These scenarios will only copy the security policy xml files. To run the
client use the script "samples/client/sec_echo/update_n_run.sh" on Linux or
"samples/client/sec_echo/update_n_run.bat" on Windows.

Following is a summary of scenarios available.

Scenario    Summary
-------------------
1.          Timestamp
2.          UsernameToken
3.          Encryption
4.          Signature
5.          A complete scenario to show: Timestamp, UsernameToken, Encrypt,
            The protection order is Sign->Encrypt
            Signature is Encrypted
6.          A complete scenario to show: Timestamp, UsernameToken, Encrypt,
            The protection order is Encrypt->Sign
            Signature is Encrypted
7.          Replay detection           

FAQ:
---
* I am NOT in LINUX. Are there any changes to be done in samples.
----------------------------------------------------------------
YES. You have to change file names accordingly. For example your password
callback module might have "*.so" as the extension. This might be different in
WIN32 and Mac OS.

* I am in a HURRY and I need to try a scenario
--------------------------------------------
If you are in a real hurry and need to try a scenario please use "test_scen.sh".
Usage : %sh test_scen.sh scenarioX server-port
E.g. %sh test_scen.sh scenario3 8080

* I need to try all the scenarios
-------------------------------
In this case please use the script run_all.sh.
Usage: %sh run_all.sh server-port
E.g. %sh run_all.sh 8080

* I need to see messages exchanged
--------------------------------------
You may use the TCP Monitor utility: http://ws.apache.org/commons/tcpmon/

Make sure that you give the correct port that you have configured in TCPMon
while running the scripts.

* I cannot run samples and log says keys cannot be loaded
---------------------------------------------------------
Check your policy files. Make sure that you have correct paths specified for
key/certificate files.

* My client sends a secured SOAP request. But the server throws me SOAP faults.
------------------------------------------------------------------------------
Well. You are on it. Check whether the server's policy configurations are
satisfied by the client's policies. There is a <Reason> element carrying the
information you need in the SOAP fault. Misconfigurations in the server also can be resulted
in a SOAP fault. 

*Hmm... I'm still in a trouble. Can I contact you guys?
-------------------------------------------------------
Indeed you can. Please check here.
http://ws.apache.org/rampart/c/lists_issues.html
Err... if you can attach log files under AXIS2C_HOME/logs, a trace of SOAP
message, plus anything that you think relavent, that'll help the troubleshooting process. 



