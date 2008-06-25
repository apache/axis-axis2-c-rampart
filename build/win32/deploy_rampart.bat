@echo off
echo -------------------------------------------------------------------------
echo deploying rampart...
echo -------------------------------------------------------------------------

md %AXIS2C_HOME%\modules\rampart\
copy modules\rampart\mod_rampart.dll %AXIS2C_HOME%\modules\rampart\
copy modules\rampart\module.xml %AXIS2C_HOME%\modules\rampart\
copy modules\rampart\mod_rampart.* %AXIS2C_HOME%\lib\

md %AXIS2C_HOME%\modules\rahas\
copy modules\rahas\mod_rahas.dll %AXIS2C_HOME%\modules\rahas\
copy modules\rahas\module.xml %AXIS2C_HOME%\modules\rahas\module.xml
copy modules\rahas\mod_rahas.* %AXIS2C_HOME%\lib\

md %AXIS2C_HOME%\services\sec_echo\
copy bin\samples\services\sec_echo\sec_echo.dll %AXIS2C_HOME%\services\sec_echo\
copy bin\samples\services\sec_echo\services.xml %AXIS2C_HOME%\services\sec_echo\

md %AXIS2C_HOME%\services\secconv_echo\
copy bin\samples\services\secconv_echo\secconv_echo.dll %AXIS2C_HOME%\services\secconv_echo\
copy bin\samples\services\secconv_echo\services.xml %AXIS2C_HOME%\services\secconv_echo\

md %AXIS2C_HOME%\services\saml_sts\
copy bin\samples\services\saml_sts\saml_sts.dll %AXIS2C_HOME%\services\saml_sts\
copy bin\samples\services\saml_sts\services.xml %AXIS2C_HOME%\services\saml_sts\

md %AXIS2C_HOME%\bin\samples\rampart\
md %AXIS2C_HOME%\bin\samples\rampart\authn_provider\
copy bin\samples\authn_provider\authn.dll %AXIS2C_HOME%\bin\samples\rampart\authn_provider\

md %AXIS2C_HOME%\bin\samples\rampart\replay_detector\
copy bin\samples\replay_detector\rdflatfile.dll %AXIS2C_HOME%\bin\samples\rampart\replay_detector\

md %AXIS2C_HOME%\bin\samples\rampart\sct_provider\
copy bin\samples\sct_provider\sctprovider.dll %AXIS2C_HOME%\bin\samples\rampart\sct_provider\
copy bin\samples\sct_provider\sctprovider_hashdb.dll %AXIS2C_HOME%\bin\samples\rampart\sct_provider\

md %AXIS2C_HOME%\bin\samples\rampart\data\
copy bin\samples\data\passwords.txt %AXIS2C_HOME%\bin\samples\rampart\data\

md %AXIS2C_HOME%\bin\samples\rampart\client\
md %AXIS2C_HOME%\bin\samples\rampart\client\sec_echo\
copy bin\samples\client\sec_echo\echo.exe %AXIS2C_HOME%\bin\samples\rampart\client\sec_echo\

md %AXIS2C_HOME%\bin\samples\rampart\client\saml_echo\
copy bin\samples\client\saml_echo\echo.exe %AXIS2C_HOME%\bin\samples\rampart\client\saml_echo\

md %AXIS2C_HOME%\bin\samples\rampart\client\issued_token\
copy bin\samples\client\issued_token\echo.exe %AXIS2C_HOME%\bin\samples\rampart\client\issued_token\

md %AXIS2C_HOME%\bin\samples\rampart\callback
copy bin\samples\callback\pwcb.dll %AXIS2C_HOME%\bin\samples\rampart\callback\

md %AXIS2C_HOME%\bin\samples\rampart\credential_provider
copy bin\samples\credential_provider\cred_provider.dll %AXIS2C_HOME%\bin\samples\rampart\credential_provider\

xcopy bin\samples\keys %AXIS2C_HOME%\bin\samples\rampart\keys\ /E /I /Y /S

copy bin\samples\services\sec_echo\server_axis2.xml %AXIS2C_HOME%\axis2.xml

echo -------------------------------------------------------------------------
echo Rampart deployed
echo -------------------------------------------------------------------------
@echo on
