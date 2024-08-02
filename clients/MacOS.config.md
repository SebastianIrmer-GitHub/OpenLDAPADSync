
### Befehle zum einstellen von macOS Maschinen 
cd "C:\Program Files\VBox"

VBoxManage.exe modifyvm "macos" --cpuidset 00000001 000106e5 00100800 0098e3fd bfebfbff 

VBoxManage setextradata "macos" "VBoxInternal/Devices/efi/0/Config/DmiSystemProduct" "iMac19,3"

VBoxManage setextradata "macos" "VBoxInternal/Devices/efi/0/Config/DmiSystemVersion" "1.0" 

VBoxManage setextradata "macos" "VBoxInternal/Devices/efi/0/Config/DmiBoardProduct" "Iloveapple"

VBoxManage setextradata "macos" "VBoxInternal/Devices/smc/0/Config/DeviceKey" "ourhardworkbythesewordsguardedpleasedontsteal(c)AppleComputerInc"

VBoxManage.exe setextradata "macos" “VBoxInternal/Devices/smc/0/Config/GetKeyFromRealSMC” 0

VBoxManage.exe setextradata "macos" “VBoxInternal/TM/TSCMode” “RealTSCOffset”


### Core Isolation ausstellen