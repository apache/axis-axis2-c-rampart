@echo off
echo -------------------------------------------------------------------------
echo deploying rampart...
echo -------------------------------------------------------------------------

md %AXIS2C_HOME%\modules\rampart\
copy modules\rampart\mod_rampart.dll %AXIS2C_HOME%\modules\rampart\
copy modules\rampart\module.xml %AXIS2C_HOME%\modules\rampart\

copy lib\rampart.* %AXIS2C_HOME%\lib\

md %AXIS2C_HOME%\modules\rahas\
copy modules\rahas\mod_rahas.dll %AXIS2C_HOME%\modules\rahas\
copy modules\rahas\module.xml %AXIS2C_HOME%\modules\rahas\module.xml

md %AXIS2C_HOME%\services\sec_echo\
copy services\sec_echo\sec_echo.dll %AXIS2C_HOME%\services\sec_echo\
copy services\sec_echo\services.xml %AXIS2C_HOME%\services\sec_echo\

md %AXIS2C_HOME%\services\secconv_echo\
copy services\secconv_echo\secconv_echo.dll %AXIS2C_HOME%\services\secconv_echo\
copy services\secconv_echo\services.xml %AXIS2C_HOME%\services\secconv_echo\

md %AXIS2C_HOME%\services\saml_sts\
copy services\saml_sts\saml_sts.dll %AXIS2C_HOME%\services\saml_sts\
copy services\saml_sts\services.xml %AXIS2C_HOME%\services\saml_sts\

md %AXIS2C_HOME%\samples\lib\
copy samples\lib\authn.dll %AXIS2C_HOME%\samples\lib\
copy samples\lib\rdflatfile.dll %AXIS2C_HOME%\samples\lib\
copy samples\lib\sctprovider.dll %AXIS2C_HOME%\samples\lib\
copy samples\lib\sctprovider_hashdb.dll %AXIS2C_HOME%\samples\lib\
copy samples\lib\pwcb.dll %AXIS2C_HOME%\samples\lib\
copy samples\lib\cred_provider.dll %AXIS2C_HOME%\samples\lib\

md %AXIS2C_HOME%\samples\data\
copy samples\data\passwords.txt %AXIS2C_HOME%\samples\data\
xcopy samples\data\keys %AXIS2C_HOME%\samples\data\keys\ /E /I /Y /S

md %AXIS2C_HOME%\samples\bin\
copy samples\bin\sec_echo.exe %AXIS2C_HOME%\samples\bin\
copy samples\bin\saml_echo.exe %AXIS2C_HOME%\samples\bin\
copy samples\bin\issued_token_echo.exe %AXIS2C_HOME%\samples\bin\

copy samples\data\server_axis2.xml %AXIS2C_HOME%\axis2.xml

echo -------------------------------------------------------------------------
echo Rampart deployed
echo -------------------------------------------------------------------------
@echo on
