Quick Info
_________________________________________________________________
cppKalkanProject - приложение для проверки и получения информации ЭЦП ключа на стороне сервера по http протоколу (http API)

Необходимые библиотеки (libkalkancryptwr-64.so или KalkanCrypt.dll) находятся в пакете SDK с сайта pki.gov.kz -
должны быть в папке libs

Настройки приложения - находятся в файле config.ini

Сборка
_________________________________________________________________
mkdir debug release
cd debug
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
cd ../release
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
