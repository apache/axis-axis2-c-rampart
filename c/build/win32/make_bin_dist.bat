set BINDIST=..\rampart-bin-0.90-win32
if exist %BINDIST% rd /s /q %BINDIST%
mkdir %BINDIST%
mkdir %BINDIST%\samples
mkdir %BINDIST%\modules
mkdir %BINDIST%\include

xcopy /E /I /Y .\bin\samples\* %BINDIST%\samples\
xcopy /E /I /Y .\modules\* %BINDIST%\modules\
xcopy /E /I /Y .\include\* %BINDIST%\include\
