### Challenge1.exe - .NET

This walkthrough details the process of **extracting and decoding a secret** from a `.NET` executable (`Challenge1.exe`) and discovering the hidden **FLAG**.

---

#### 1. **Opening `Challenge1.exe` with DnSpy**

- Start by opening the executable file `Challenge1.exe` in **DnSpy**, a popular .NET decompiler.
  - DnSpy allows us to view the source code of .NET applications, which helps reverse engineer the logic behind the challenge.

---

#### 2. **Navigating to the Embedded Secret in Resources**

- In DnSpy, expand the **Resources** section.
  - Look for a resource named **`rev_challenge_1.dat_secret.encode`**.
  - This is the embedded file containing the encoded secret.
  
- **Save the binary resource** by right-clicking on it and selecting **Save**.

---

#### 3. **Inspecting the Secret with DIE**

- Next, open the saved resource file (`rev_challenge_1.dat_secret.encode`) with **DIE (Detect It Easy)**, a tool used to analyze file structures and display their hexadecimal content.
  
- The secret is encoded in **hexadecimal format** and can be seen as a string of bytes:
  ```
  a1b5448414e4a1b5d470b491b470d491e4c496f45484b5c440647470a46444
  ```
  - These hexadecimal values represent the encoded secret hidden within the resource.

---

#### 4. **Decoding the Secret with a Python Script**

- Use the provided Python script, **`ch_1_sol.py`**, to decode the secret.
  - The hex-encoded string is passed as input to the script.

- Upon successful execution of `ch_1_sol.py`, the **decoded FLAG** is revealed:
  ```
  FLAG: 3rmahg3rd.b0b.d0ge@flare-on.com
  ```

---

### Conclusion

This process involved using **DnSpy** to extract an embedded resource from a .NET executable, inspecting the resource with **DIE** to view its hex-encoded contents, and then using a Python script to decode and reveal the hidden **FLAG**. The decoded flag is a **coded email address**, which is the intended solution for this challenge.

Let me know if you'd like to dive deeper into any specific part of the process or need additional assistance!
