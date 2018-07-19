binsecurity
=========

binsecurity - Python script to check if Windows Binary (EXE/DLL) has ASLR,DEP,SafeSEH

```
Usage: ./binsecurity -h
```
```
Dependencie pefile 
pip install pefile
```

```
Check Binary

C:\python binsecurity -b putty.exe 
```
![alt tag](https://cdn-images-1.medium.com/max/800/1*QJqvbWIwoeMBNK7XGkEhmA.png)
```
Check DLL import by binary

C:\python binsecurity -b putty.exe -c (or --check)
```
![alt tag](https://cdn-images-1.medium.com/max/800/1*AfnxubMW2DF4KKG5beAXlQ.png)
```
Check a directory for DLLs

C:\python binsecurity -d C:\Windows\System32
```
