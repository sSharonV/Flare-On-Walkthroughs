# Decoding `home.html` Walkthrough

In this guide, we’ll break down the process of analyzing `home.html` to extract and decode hidden content. This walkthrough will detail the steps needed to examine embedded PHP code and decode the scripts using Python.

## Table of Contents
1. [Introduction](#introduction)
2. [Step 1: Inspect `home.html` with a Browser's Developer Tools](#step-1-inspect-homehtml-with-a-browsers-developer-tools)
3. [Step 2: Examine `flare-on.png` for Embedded PHP Code](#step-2-examine-flare-onpng-for-embedded-php-code)
4. [Step 3: Analyze the Initial `do_me` Statement and Extract JavaScript](#step-3-analyze-the-initial-do_me-statement-and-extract-javascript)

---

## Introduction

This walkthrough focuses on analyzing the `home.html` file to uncover a hidden script embedded as a PNG file using PHP. The PHP code within the PNG is then processed to reveal a JavaScript snippet. We'll use tools like a hex editor and Python scripts to decode and understand these hidden components.

---

## Step 1: Inspect `home.html` with a Browser's Developer Tools

1. Open `home.html` in a browser with developer tools enabled.
2. Locate the PHP include statement embedded between `<script>` tags in the HTML source:
   ```html
   </script>
   ** <?php include "img/flare-on.png" ?> **
   <script type="text/javascript">
   ```
   - This is an unconventional way of embedding a PNG file as PHP code, which is suspicious and may indicate hidden content or a payload.

---

## Step 2: Examine `flare-on.png` for Embedded PHP Code

1. Open `flare-on.png` in a hex editor and navigate to offset `19c4` to locate any embedded PHP code.
2. Extract the PHP code from the PNG and save it as `1_php.php`.
3. Convert the extracted PHP code into a Python format and save it as `1_php.py` for further analysis.

---

## Step 3: Analyze the Initial `do_me` Statement and Extract JavaScript

1. Run the Python script `1_php.py` to print the first `do_me` statement that would be executed.
2. Save the next JavaScript code block that is printed by `1_php.py` as `2_js.py` for further investigation.
3. Use `2_decode.py` to deobfuscate the JavaScript code, revealing the true content.
4. After deobfuscation, the following PHP code snippet is exposed:
   ```php
   base64_decode(
       $code=base64_decode(if(isset($_POST["a11DOTthatDOTjava5crapATflareDASHonDOTcom"])); });
   eval($code);
   ```
