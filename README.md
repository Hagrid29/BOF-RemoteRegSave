# BOF - RemoteRegSave

A fork of [RegSave BOF](https://github.com/EncodeGroup/BOF-RegSave). Dump SAM/SYSTEM/SECURITY registry key hives on local or remote computer for offline parsing and hash extraction..



### Usage

Dump registry key hives on local computer (admin elevation required)

```
RegSave --path [file path <optional>]
```

Dump registry key hives on remote computer (automatically enable service RemoteRegistry if disabled)

```
RegSave --pc remotePC --path [file path <optional>]
shell copy \\remoteSrv\C$\Windows\temp\HG029* .
```



### Compile

```linux
cd SOURCE
make
```



### References

+ [RegSave BOF](https://github.com/EncodeGroup/BOF-RegSave)
+ [SharpSecDump](https://github.com/G0ldenGunSec/SharpSecDump)