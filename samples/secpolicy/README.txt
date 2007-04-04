The scenarios available here can be deployed using either deploy.sh(UNIX) or
deploy.bat(WIN32).

Simply give the scenario name as an argument to the script
e.g. %sh deploy.sh scenario1 

Make sure you have run the deploy_client_repo.sh.

These scenarios will only copy the security policy xml files. To run the
client use the script samples/client/sec_echo/update_n_run.sh or
samples/client/sec_echo/update_n_run.bat

Following is a summary of scenarios available.

Scenario    Summary
-------------------
1.          Timestamp
2.          UsernameToken
3.          Client Encrypt(DirectReference)        
4.          Client Encrypt(IssuerSerial/RefKeyIdentifier/Embedded)           
5.          Client Sign(DirectReference)        
6.          Client Sign(IssuerSerial/RefKeyIdentifier/Embedded)           
7.          Timestamp, UsernameToken, Encrypt, Sign (Encrypt before sign/ Sign
before encrypt)
8.          A complete scenario, where both client and server encrypt/sign,
add Timestamps, Usernametokens.

