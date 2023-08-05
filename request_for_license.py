import subprocess
import pystyle
import os    
p = subprocess.Popen('wmic csproduct get uuid', stdout=subprocess.PIPE)
out, _ = p.communicate()
hwid = out.decode().split('\n')[1].strip()
os.system("cls")
pystyle.Write.Print("[*] Request Key = " + hwid, pystyle.Colors.yellow, interval=0)
pystyle.Write.Print("\n[*] Please send this key to the owner of the tool in order to get your license key.", pystyle.Colors.green, interval=0)
pystyle.Write.Print("\n[*] Mod by General ZodX | General ZodX @ YouTube ", pystyle.Colors.cyan, interval=0)
