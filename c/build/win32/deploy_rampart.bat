md %AXIS2C_HOME%\modules\rampart\
copy rampart\mod_rampart.dll %AXIS2C_HOME%\modules\rampart\
copy rampart\module.xml %AXIS2C_HOME%\modules\rampart\

md %AXIS2C_HOME%\services\sec_echo\
copy bin\samples\services\sec_echo\sec_echo.dll %AXIS2C_HOME%\services\sec_echo\
copy bin\samples\services\sec_echo\services.xml %AXIS2C_HOME%\services\sec_echo\

md %AXIS2C_HOME%\bin\samples\rampart\
md %AXIS2C_HOME%\bin\samples\rampart\authn_provider
copy bin\samples\authn_provider\authn.dll %AXIS2C_HOME%\bin\samples\rampart\authn_provider\

