# AspiaHWInfo

Export hardware information from Aspia host to JSON file 

Usage
-------------------

```
AspiaHWInfo -nupx[tvjh]

Required arguments:
  -n=<..>, --network=<..>            TCP/IP network [:port] for scan
  -u=<..>, --hostUser=<..>           Aspia host user name
  -p=<..>, --hostPassword=<..>       Aspia host user password
  -x=<..>, --export=<..>             Export scan results to JSON-file

Optional arguments:
  -l=<..>, --limit=<..>              Limitation on exporting event log entries to JSON-file
  -a=<..>, --all=<..>                Export all data to JSON-file
  -t=<..>, --timeout=<..>            Timeout in milliseconds (min: 200, max 5000)
  -v,      --version                 print AspiaHWInfo version
  -j,      --java                    print Java version
  -h,      --help                    this help
```

Usage example:
--------------

```sh
  AspiaHWInfo -n=192.168.1.0/24:8050 -u=AspiaUser -p=Pa$$word -x="d:\hwinfo.json"
```

Direct run
----------

Linux/MacOS
``` sh
/Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home/bin/java -cp "AspiaBook/lib/*" info.malenkov.aspiahwinfo.AspiaHWInfo -n=192.168.1.0/24:8050 -u=AspiaUser -p=Pa$$word -x="~/hwinfo.json"
```

Windows
``` sh
C:\PROGRA~1\Zulu\zulu-8\bin\java.exe -cp AspiaHWInfo\lib\* info.malenkov.aspiahwinfo.AspiaHWInfo -n=192.168.1.0/24:8050 -p=NewPa$$word -w="d:\newBook.aab"
```

System requirements
-------------------
- Java 8 or higher 

Contacts
--------
E-Mail: maxim.v.malenkov@gmail.com

Licensing
---------
Project code is available under the GNU General Public License 2.
