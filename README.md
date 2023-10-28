# Memory Forensics with Volatility
> https://www.volatilityfoundation.org/releases

<br>

## Obtaining Memory Samples

### Live machines
- memory image extractor
```
 FTK Imager
 Redline
 DumpIt.exe
 win32dd.exe / win64dd.exe (psexec)
```
- these tools will typically output a `.raw` file

### Offline machines
- windows:
  - _windows hibernation file_ (`%SystemDrive%/hiberfil.sys`) stores compressed memory image from previous boot

### Virtual machines
- memory images
```
 VMware - .vmem file
 Hyper-V - .bin file
 Parallels - .mem file
 VirtualBox - .sav file
```
- can be found on data store of the corresponding hypervisor & can be copied without shuting vm off
- allows for virtually zero disturbance to the virtual machine, preserving it's forensic integrity


<br>

## [Eg.] examine `.vmem` memory sample
> [download memory sample](cridexmemdump.zip)

### Basic commands

|command|details|
|---|---|
|`volatility -f MEMORY_FILE.raw imageinfo`|Profiles determine how _volatility_ treats our memory image since every version of windows is a little bit different.|
|`volatility -f MEMORY_FILE.raw --profile=PROFILE pslist`|Test these profiles using the pslist command, validating our profile selection by the sheer number of returned results.|
|`volatility -f MEMORY_FILE.raw --profile=PROFILE netscan`|View active network connections at the time of image creation.|
|`volatility -f MEMORY_FILE.raw --profile=PROFILE psxview`|View intentionally hidden processes.|
|`volatility -f MEMORY_FILE.raw --profile=PROFILE ldrmodules`|In addition to viewing hidden processes via psxview, we can also check this with a greater focus via the command 'ldrmodules'. Three columns will appear here in the middle, InLoad, InInit, InMem. If any of these are false, that module has likely been injected which is a really bad thing. On a normal system the grep statement above should return no output.|
|`volatility -f MEMORY_FILE.raw --profile=PROFILE apihooks`|View unexpected patches in the standard system DLLs. If we see an instance where Hooking module: <unknown> that's really bad. This command will take a while to run, however, it will show you all of the extraneous code introduced by the malware.|
|`volatility -f MEMORY_FILE.raw --profile=PROFILE malfind -D <Destination Directory>`|Injected code can be a huge issue and is highly indicative of very very bad things. With `malfind` command, we can not only find this code, but also dump it to our specified directory.|
|`volatility -f MEMORY_FILE.raw --profile=PROFILE dlllist`|List all of the DLLs in memory.|
|`volatility -f MEMORY_FILE.raw --profile=PROFILE --pid=PID dlldump -D`|Dump the DLLs running in memory, where the PID is the process ID of the infected process|


### Post actions
- we spoted & extracted malicious code from infected process (done with basic forensics)
- now upload to code to [VirusTotal](https://www.virustotal.com/gui/home/upload) or [Hybrid Analysis](https://www.hybrid-analysis.com/) for checking any previous matches of malware

