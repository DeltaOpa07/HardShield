# 0. HardShield
   Here is HardShield v1.0, it's a project that i started few days ago to learn how ransomware works
# 1. Introduction
   1. This thread is for me to record the updates of my first ransomware on my own
   2. It's open source and upload to Github after i write it every time
   3. Hope to receive advice and guidance from predecessors
   4. The will always update once i have time, but i can't promise the update
# 2. Features & Components
   The HardShield ransomware has three parts currently, including:
   1. **Builder(VC++):** 
      a. you can setup a ransom mail on it
      b. build decryptor, encryptor, and generate keys
   2. **Encryptor(C or Intel assembly): **
      a. encrypt all image or data files(won't destroy the system) by CBC AES128+RSA2048, unbreakable
      b. after encryption is over, it will popup a dialog and show the ransom info like wannacry
      c. it steals all data from the victim and send back to server
      d. change the desktop image
      e. delete volume shadow copy and clean the recycle bin
      f. kill active processes and stop services which will be against the encryption
      g. multithread encryption
      h. encrypt net disk files and removable device
      i. Self-delete after all done
   3. **Decryptor(C or Intel assembly):**
      Decrypt the selected files or directories, of course you can choose to decrypt all files on your disk
      multithread decryption
# 3. Legal Disclaimer
   Usage of the code from this repository for attacking targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
