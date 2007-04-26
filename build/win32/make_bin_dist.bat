set BINDIST = ..\rampart-bin-0.90-win32
if exist %BINDIST% rd /s /q %BINDIST%
mkdir %BINDIST%

xcopy /E /I /Y bin\samples\ %BINDIST%\samples\
xcopy /E /I /Y bin\modules\ %BINDIST%\modules\
