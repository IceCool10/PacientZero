g++ -o stub.exe stub.cpp Parser.cpp util.cpp asm2.obj tls.obj -Iaplib\lib\coff64\ -Laplib\lib\coff64\ -laplib
g++ -o main.exe main.cpp Parser.cpp util.cpp asm2.obj -Iaplib\lib\coff64\ -Laplib\lib\coff64\ -laplib
