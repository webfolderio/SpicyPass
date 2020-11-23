if not exist "c:\gtk-build" (
  mkdir C:\gtk-build\gtk\Win32
  if not exist "gtk3.24.17-vs15-x86.tar.gz" (             
    curl -L "https://github.com/webfolderio/gtk-windows/releases/download/3.24.17/gtk3.24.17-vs15-x86.tar.gz" --output gtk3.24.17-vs15-x86.tar.gz
  )
  tar -xzf gtk3.24.17-vs15-x86.tar.gz -C "C:\gtk-build\gtk\Win32"
)

vcpkg install libsodium:x86-windows
vcpkg install libsodium:x86-windows-static
mkdir build-console
cd build-console
set VCPKG_ROOT=C:\tools\vcpkg
cmake ^
 -DCMAKE_BUILD_TYPE=Release ^
 -DLIBSODIUM_INCLUDE_DIRS="%VCPKG_ROOT%\installed\x86-windows-static\include" ^
 -DLIBSODIUM_LIBRARIES="%VCPKG_ROOT%\installed\x86-windows-static\lib\libsodium.lib" ^
 ..
cmake --build . --target spicypass --config Release
cd ..

mkdir build-gui
cd build-gui
set VCPKG_ROOT=C:\tools\vcpkg
set GTK_INCLUDE=C:\gtk-build\gtk\Win32\release\include
set GTK_LIB=C:\gtk-build\gtk\Win32\release\lib
set GLIB_CONF=C:\gtk-build\gtk\Win32\release\lib\glib-2.0\include
cmake ^
 -DCMAKE_BUILD_TYPE=Debug ^
 -DGTK_FOUND=ON ^
 -DLIBSODIUM_INCLUDE_DIRS="%VCPKG_ROOT%\installed\x86-windows\include" ^
 -DGTK_INCLUDE_DIRS="%GTK_INCLUDE%\gtk-3.0;%GLIB_CONF%;%GTK_INCLUDE%\glib-2.0;%GTK_INCLUDE%\pango-1.0;%GTK_INCLUDE%\harfbuzz;%GTK_INCLUDE%\cairo;%GTK_INCLUDE%\gdk-pixbuf-2.0;%GTK_INCLUDE%\atk-1.0" ^
 -DLIBSODIUM_LIBRARIES="%VCPKG_ROOT%\installed\x86-windows\lib\libsodium.lib" ^
 -DGTK_LIBRARIES="%GTK_LIB%\gtk-3.0.lib;%GTK_LIB%\gobject-2.0.lib;%GTK_LIB%\glib-2.0.lib;%GTK_LIB%\gdk-3.0.lib;%GTK_LIB%\gdk_pixbuf-2.0.lib" ^
 ..
cmake --build . --target spicypass --config Release
cd ..

mkdir dist\gui
mkdir dist\gui\icon
mkdir dist\gui\gui
mkdir dist\gui\bin
copy gui\*.* dist\gui\gui
copy icon\*.* dist\gui\icon
cd dist
cd gui
xcopy "C:\gtk-build\gtk\Win32\release" . /sy 1>NUL
del bin\*.exe
del bin\gdbus-codegen
del bin\glib-genmarshal
del bin\glib-mkenums
del bin\gtester-report
del bin\tiff.dll
del bin\tiffxx.dll
del bin\pkgconf-3.dll
del /s /q *.lib
del /s /q *.pdb
del /s /q *.pc
rmdir include /s /q
rmdir libexec /s /q
rmdir share\aclocal /s /q
rmdir share\doc /s /q
rmdir share\installed-tests /s /q
rmdir share\man /s /q
rmdir share\locale /s /q
rmdir share\pkgconfig /s /q
rmdir share\themes\Emacs /s /q
rmdir lib\pkgconfig /s /q
rmdir lib\libpng /s /q
rmdir lib\cmake /s /q
rmdir lib\glib-2.0 /s /q
cd ..
cd ..
copy build-gui\Release\*.* dist\gui\bin
mkdir dist\console
copy build-console\Release\*.* dist\console
