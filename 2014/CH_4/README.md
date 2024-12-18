# Flare-On 2014 Challenge 4: Malicious PDF with Embedded Shellcode

This walkthrough details the process of analyzing a **malicious PDF** that contains **JavaScript** and **shellcode**. The goal is to extract and execute the shellcode to reveal the hidden **FLAG**. Tools such as **pdf-parser**, **DIE**, **IDA Pro**, and custom Python scripts are utilized throughout the process.

---

## Table of Contents
- [Introduction](#introduction)
- [Step 1: Initial PDF Analysis with pdf-parser](#step-1-initial-pdf-analysis-with-pdf-parser)
- [Step 2: Investigating PDF Objects](#step-2-investigating-pdf-objects)
- [Step 3: Extracting and Deobfuscating the JS](#step-3-extracting-and-deobfuscating-the-js)
- [Step 4: Analyzing the JS and extract the Shellcode](#step-4-analyzing-the-js-and-extract-the-shellcode)
- [Step 5: Correcting Byte Order: Little Endian](#step-5-correcting-byte-order-little-endian)
- [Step 6: Converting Shellcode to Executable](#step-6-converting-shellcode-to-executable)
- [Step 7: Debugging the Shellcode](#step-7-debugging-the-shellcode)
- [Step 8: The FLAG](#step-8-the-flag)
- [References](#references)

---

## Introduction

In this challenge, we are tasked with analyzing a **malicious PDF** that contains embedded **JavaScript** and **shellcode**. The JavaScript is obfuscated, and the shellcode is hidden within the PDF. Our goal is to extract the shellcode, execute it, and reveal the hidden **FLAG**. We will utilize **pdf-parser** for initial analysis, along with **DIE**, **IDA Pro**, and custom Python scripts for deobfuscating and analyzing the shellcode.

---

## Step 1: Initial PDF Analysis with pdf-parser

We begin by analyzing the PDF with **pdf-parser** to search for embedded actions or scripts:

- Execute the following command to search for the string `'action'` within the PDF:
  ```bash
  pdf-parser.py APT9001.pdf -s action
  ```
  - This command searches for any actions or embedded JavaScript that might be present.
  
    ![Action Objects](images/1-action-objects.png)

- The output shows several objects, indicating that the PDF may contain JavaScript or other embedded actions.

---

## Step 2: Investigating PDF Objects

Next, we investigate object 6 - `JavaScript` object within the PDF:

- Run the following command to display verbose output for objects 1 and 5:
  ```bash
  pdf-parser.py APT9001.pdf -o 6 -c -D -v
  ```

- Object **6** is found to contain a **JavaScript reference**, but the content is **obfuscated**.
  
  ![Obfuscated JS](images/3-obfuscated-JS.png)

---

## Step 3: Extracting and Deobfuscating the JS

1. Now, we extract the obfuscated JavaScript content and attempt to deobfuscate it:
    - Dump the content of object **6** with the following command:
      ```bash
      pdf-parser.py APT9001.pdf -o 6 -d obfu_js.mal
      ```
      - This saves the obfuscated content that **pdf-parser** couldn't fully decode.

    - After dumping the content, we used **DIE** (Detect It Easy) to identify the encoding, which turns out to be a **zlib archive**.
- Decompressing the archive with the **extract_js_from_zlib.py** script allowed us to decode the hexadecimal values into ASCII.
  - The result was saved as `deobfu_ascii_js.js`, which still had some unclear parts.
  ![Phases of decodeing JS payload](images/3-before-deobfuscared-JS.png)
  

---

## Step 4: Analyzing the JS and extract the Shellcode

- The content looked like:
  
  ```javascript
  var HdPN = "";
  var zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf = "";
  var IxTUQnOvHg = unescape("%u72f9%u4649%u1525%u7f0d%u3d3c%ue084%ud62a%ue139%ua84a%u76b9%u9824%u7378%u7d71%u757f%u2076%u96d4%uba91%u1970%ub8f9%ue232%u467b%u9ba8%ufe01%uc7c6%ue3c1%u7e24%u437c%ue180%ub115%ub3b2%u4f66%u27b6%u9f3c%u7a4e%u412d%ubbbf%u7705%uf528%u9293%u9990%ua998%u0a47%u14eb%u3d49%u484b%u372f%ub98d%u3478%u0bb4%ud5d2%ue031%u3572%ud610%u6740%u2bbe%u4afd%u041c%u3f97%ufc3a%u7479%u421d%ub7b5%u0c2c%u130d%u25f8%u76b0%u4e79%u7bb1%u0c66%u2dbb%u911c%ua92f%ub82c%u8db0%u0d7e%u3b96%u49d4%ud56b%u03b7%ue1f7%u467d%u77b9%u3d42%u111d%u67e0%u4b92%ueb85%u2471%u9b48%uf902%u4f15%u04ba%ue300%u8727%u9fd6%u4770%u187a%u73e2%ufd1b%u2574%u437c%u4190%u97b6%u1499%u783c%u8337%ub3f8%u7235%u693f%u98f5%u7fbe%u4a75%ub493%ub5a8%u21bf%ufcd0%u3440%u057b%ub2b2%u7c71%u814e%u22e1%u04eb%u884a%u2ce2%u492d%u8d42%u75b3%uf523%u727f%ufc0b%u0197%ud3f7%u90f9%u41be%ua81c%u7d25%ub135%u7978%uf80a%ufd32%u769b%u921d%ubbb4%u77b8%u707e%u4073%u0c7a%ud689%u2491%u1446%u9fba%uc087%u0dd4%u4bb0%ub62f%ue381%u0574%u3fb9%u1b67%u93d5%u8396%u66e0%u47b5%u98b7%u153c%ua934%u3748%u3d27%u4f75%u8cbf%u43e2%ub899%u3873%u7deb%u257a%uf985%ubb8d%u7f91%u9667%ub292%u4879%u4a3c%ud433%u97a9%u377e%ub347%u933d%u0524%u9f3f%ue139%u3571%u23b4%ua8d6%u8814%uf8d1%u4272%u76ba%ufd08%ube41%ub54b%u150d%u4377%u1174%u78e3%ue020%u041c%u40bf%ud510%ub727%u70b1%uf52b%u222f%u4efc%u989b%u901d%ub62c%u4f7c%u342d%u0c66%ub099%u7b49%u787a%u7f7e%u7d73%ub946%ub091%u928d%u90bf%u21b7%ue0f6%u134b%u29f5%u67eb%u2577%ue186%u2a05%u66d6%ua8b9%u1535%u4296%u3498%ub199%ub4ba%ub52c%uf812%u4f93%u7b76%u3079%ubefd%u3f71%u4e40%u7cb3%u2775%ue209%u4324%u0c70%u182d%u02e3%u4af9%ubb47%u41b6%u729f%u9748%ud480%ud528%u749b%u1c3c%ufc84%u497d%u7eb8%ud26b%u1de0%u0d76%u3174%u14eb%u3770%u71a9%u723d%ub246%u2f78%u047f%ub6a9%u1c7b%u3a73%u3ce1%u19be%u34f9%ud500%u037a%ue2f8%ub024%ufd4e%u3d79%u7596%u9b15%u7c49%ub42f%u9f4f%u4799%uc13b%ue3d0%u4014%u903f%u41bf%u4397%ub88d%ub548%u0d77%u4ab2%u2d93%u9267%ub198%ufc1a%ud4b9%ub32c%ubaf5%u690c%u91d6%u04a8%u1dbb%u4666%u2505%u35b7%u3742%u4b27%ufc90%ud233%u30b2%uff64%u5a32%u528b%u8b0c%u1452%u728b%u3328%ub1c9%u3318%u33ff%uacc0%u613c%u027c%u202c%ucfc1%u030d%ue2f8%u81f0%u5bff%u4abc%u8b6a%u105a%u128b%uda75%u538b%u033c%uffd3%u3472%u528b%u0378%u8bd3%u2072%uf303%uc933%uad41%uc303%u3881%u6547%u5074%uf475%u7881%u7204%u636f%u7541%u81eb%u0878%u6464%u6572%ue275%u8b49%u2472%uf303%u8b66%u4e0c%u728b%u031c%u8bf3%u8e14%ud303%u3352%u57ff%u6168%u7972%u6841%u694c%u7262%u4c68%u616f%u5464%uff53%u68d2%u3233%u0101%u8966%u247c%u6802%u7375%u7265%uff54%u68d0%u786f%u0141%udf8b%u5c88%u0324%u6168%u6567%u6842%u654d%u7373%u5054%u54ff%u2c24%u6857%u2144%u2121%u4f68%u4e57%u8b45%ue8dc%u0000%u0000%u148b%u8124%u0b72%ua316%u32fb%u7968%ubece%u8132%u1772%u45ae%u48cf%uc168%ue12b%u812b%u2372%u3610%ud29f%u7168%ufa44%u81ff%u2f72%ua9f7%u0ca9%u8468%ucfe9%u8160%u3b72%u93be%u43a9%ud268%u98a3%u8137%u4772%u8a82%u3b62%uef68%u11a4%u814b%u5372%u47d6%uccc0%ube68%ua469%u81ff%u5f72%ucaa3%u3154%ud468%u65ab%u8b52%u57cc%u5153%u8b57%u89f1%u83f7%u1ec7%ufe39%u0b7d%u3681%u4542%u4645%uc683%ueb04%ufff1%u68d0%u7365%u0173%udf8b%u5c88%u0324%u5068%u6f72%u6863%u7845%u7469%uff54%u2474%uff40%u2454%u5740%ud0ff");
  var MPBPtdcBjTlpvyTYkSwgkrWhXL = "";
  ```
- Before trying to decode all the script let's focus on the escaped strings:
- Use the **deobfu_escaped.py** script
  -  Converts **%uXXXX** Unicode escapes into actual ASCII characters:

 1. `little_endian_encoded_shellcode.bin`
    
    ![Little-Endian encoding](images/4-encoded-little-endian-sc.png)

    - _Notice_: The data is shown in reversed order (big-endian)
                -  [Little-Endian in IDA - binary search](https://hex-rays.com/blog/igors-tip-of-the-week-48-searching-in-ida)

  - The script will also decode little-endian dumped binary data (from big-endian to little-endian)
---

## Step 5: Correcting Byte Order: Little Endian

2. `little_endian_decoded_shellcode.bin`
   
    - Reverse any pair of hex-values
      
      ![Little-Endian decoding](images/4-decoded-little-endian-sc.png)

---

## Step 6: Converting Shellcode to Executable

A shellcode cannot be executed without an executable that will make it happen.

- Using the **shcode2exe** script from GitHub, we converted the shellcode into an executable:
  ```bash
  python ./shcode2exe.py -o little_endian_sc.exe little_endian_decoded_shellcode.bin
  ```

  - **Shellcode to EXE - GitHub**: [shcode2exe](https://github.com/accidentalrebel/shcode2exe)

---

## Step 7: Debugging the Shellcode

We now analyze the **little_endian_sc.exe** in **IDA Pro**:
   - Open the executable in **IDA** and track the flow of the shellcode.
   - By stepping through the instructions, we encountered an error while attempting to perform XOR operation (probably because we're not exploiting the vulnerable PDF reader that was meant for this challenge)
     
      ![Memory error](images/6-error-on-xor.png)
      
---

## Step 8: The FLAG

To bypass this issue i've wrote a Python script to decrypt the values which revealed the **FLAG**
  - Execute `build_xored.py`
    
      ![Flag](images/8-flag.png)



- **FLAG**:
  ```  
  wa1ch.d3m.spl01ts@flare-on.com
  ```

---

### References

- **pdf-parser**: A tool for analyzing and parsing PDF files.
- **DIE (Detect It Easy)**: A tool for detecting file types and analyzing embedded content.
- **IDA Pro**: A disassembler and debugger for reverse engineering tasks.
- **shcode2exe**: A script for converting raw shellcode into executable files.
