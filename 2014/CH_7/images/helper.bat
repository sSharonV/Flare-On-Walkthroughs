@echo off
setlocal enabledelayedexpansion

rem Loop through each PNG file in the directory
for %%f in (*.png) do (
    rem Get the filename without the extension
    set "filename=%%~nf"
    
    rem Replace spaces with a single hyphen and remove any leading or trailing hyphens
    set "newname="
    for %%i in (!filename!) do (
        set "part=%%i"
        rem If part is not empty, append it to the newname with a hyphen
        if defined part (
            if defined newname (
                set "newname=!newname!-!part!"
            ) else (
                set "newname=!part!"
            )
        )
    )

    rem Rename the file
    ren "%%f" "!newname!.png"
)

endlocal
