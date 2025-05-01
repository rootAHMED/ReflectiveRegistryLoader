## Technique Overview
- Stores encrypted payload in Windows Registry  
- Retrieves and decrypts payload via `SystemFunction032` (RC4)  
- Executes reflectively without file artifacts  
- Bypasses basic signature-based detection  

## Detection Indicators
- Registry writes to `HKCU\Console\*`  
- Usage of `SystemFunction032`  
- Memory protection changes (`PAGE_EXECUTE_READWRITE`)  

Let's take a look at the memory address with 276 bytes using WinDbg:
![Screenshot 2025-05-01 231208](https://github.com/user-attachments/assets/7890e071-c928-4244-a19e-0b31708d0649)
![Screenshot 2025-05-01 231317](https://github.com/user-attachments/assets/c74b549c-e7e9-4f45-9872-03f8ff024284)
![Screenshot 2025-05-01 231259](https://github.com/user-attachments/assets/c295b69f-d74e-4514-a63f-3240c544ef94)

# Resources
- **RC4 Encryption via SystemFunction032**  
  [Rc4EncryptionViaSystemFunc032](https://gist.github.com/MattiaCossu/490595b519660318c53bd6e41d5e798c)  
- **Writing & Reading to Windows Registry with Windows API**  
  [Writing & Reading to Windows Registry](https://stackoverflow.com/questions/48428728/writing-reading-to-windows-registry-with-windows-api?utm_source)  
- **Techniques and Resources**  
  [MalwareTech](https://malwaretech.com/)  
  [Awesome EDR Bypass - GitHub](https://github.com/tkmru/awesome-edr-bypass)
