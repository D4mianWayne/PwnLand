# PwnLand

<div align="center">
  <img src="https://img.shields.io/badge/PwnFuzz-Open%20Source%20R%2FD-blue" alt="PwnFuzz">
  <img src="https://img.shields.io/badge/Focus-Exploitation%20Development-red" alt="Focus">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
</div>

## Overview

PwnLand is an open-source repository maintained by PwnFuzz, an R&D lab specializing in fuzzing, reverse engineering, vulnerability research, and exploit development. This repository serves as a comprehensive resource for security researchers, CTF players, and anyone interested in binary exploitation.

PwnLand contains practical examples, tutorials, CTF writeups, and research materials covering various aspects of binary exploitation, including:

- Buffer Overflows and ROP Chains
- Format String Vulnerabilities
- Heap Exploitation Techniques
- Kernel Exploitation
- Assembly Language Fundamentals
- Binary Debugging Strategies

Whether you're a beginner or an experienced security researcher, PwnLand provides hands-on materials to enhance your understanding of exploitation techniques across different environments and security mechanisms.

## Table of Contents

- [Directory Structure](#directory-structure)
- [Exploitation Techniques](#exploitation-techniques)
  - [Buffer Overflows](#buffer-overflows)
  - [Format String](#format-string)
  - [Heap Exploitation](#heap-exploitation)
  - [Kernel Exploitation](#kernel-exploitation)
    - [Kernel Exploitation Primer Series](#kernel-exploitation-primer-series)
- [CTF Writeups](#ctf-writeups)
- [Research Materials](#research-materials)
- [Assembly Resources](#assembly-resources)
- [Debugging Guides](#debugging-guides)
- [Challenges](#challenges)
- [Getting Started](#getting-started)
- [Contributing](#contributing)
- [License](#license)

## Directory Structure

```
.
├── Assembly/              # Assembly language fundamentals
├── Attachments/           # Supporting images and resources
├── binaries/              # Example binaries for practice
├── BufferOverflows/       # Buffer overflow techniques and examples
├── Challenges/            # Practice challenges
├── CTFs/                  # Writeups and solutions for CTF challenges
├── Debugging/             # Debugging techniques and guides
├── Format String/         # Format string vulnerability tutorials
├── Heap/                  # Heap exploitation techniques
├── Kernel/                # Kernel exploitation examples
└── Research/              # Deep dives into exploitation concepts
```

## Exploitation Techniques

### Buffer Overflows

Navigate to [BufferOverflows/](./BufferOverflows/) to explore:

- **Basic Overflow Techniques**
  - [Basic Buffer Overflow](./BufferOverflows/Basic%20Overflow/basic_overflow.md)
  - [File Pointer Overwrite](./BufferOverflows/Basic%20Overflow/overwrite_filepointer.md)
  - [gets() Vulnerability](./BufferOverflows/gets.md)

- **Return-to-libc Attacks**
  - [32-bit Return-to-libc without ASLR](./BufferOverflows/ret2libc/32bit/ret2libc-no-aslr.md)
  - [32-bit Return-to-libc with ASLR](./BufferOverflows/ret2libc/32bit/ret2libc-aslr.md)

- **Return-Oriented Programming (ROP)**
  - [32-bit Basic ROP](./BufferOverflows/ROP/rop-32bit-basic.md)
  - [64-bit Basic ROP](./BufferOverflows/ROP/rop-64bit-basic.md)

- **Additional Resources**
  - [Resources and References](./BufferOverflows/resources.md)

### Format String

Navigate to [Format String/](./Format%20String/) to learn about:

- [Introduction to Format String Vulnerabilities](./Format%20String/introduction.md)
- [GOT Overwrite to System](./Format%20String/overwrite-got-system.md)
- [Writing Shellcode to BSS](./Format%20String/shellcode-bss-write.md)
- [Variable Value Overwrite](./Format%20String/variable-value-overwrite.md)

### Heap Exploitation

Navigate to [Heap/](./Heap/) for techniques organized by GLIBC version:

- **GLIBC 2.23**
  - [Fastbin Dup](./Heap/GLIBC%202.23/Fastbin%20Dup/)
  - [House of Force](./Heap/GLIBC%202.23/House_Of/House_Of_Force/)
  - [Use After Free (UAF)](./Heap/GLIBC%202.23/UAF/)
  - [Unsafe Unlink](./Heap/GLIBC%202.23/Unsafe%20Unlink/)

- **GLIBC 2.27**
  - [Double Free](./Heap/GLIBC%202.27/Double%20Free/)
  - [Nullbyte Overflow](./Heap/GLIBC%202.27/Nullbyte%20Overflow/)
  - [Overlapping Chunks](./Heap/GLIBC%202.27/Overlapping%20Chunks/)

### Kernel Exploitation

Navigate to [Kernel/](./Kernel/) to explore:

- [HEVD Buffer Overflow](./Kernel/HEVD/HEVD_IOCTL_BUFFER_OVERFLOW_STACK.md)
- [OTAu-lab10c Challenge](./Kernel/OTAu-lab10c/README.md)

#### Kernel Exploitation Primer Series

This section was contributed by [Nikhil](https://github.com/ghostbyt3). The following blog posts are beginner-friendly and offer in-depth guidance for those starting out with Windows kernel exploitation on modern systems.

- [Kernel Exploitation Primer 0x0 - Windows Driver 101](https://ghostbyt3.github.io/blog/Kernel_Exploitation_Primer_0x0)
- [Kernel Exploitation Primer 0x1 - Setup & Reversing](https://ghostbyt3.github.io/blog/Kernel_Exploitation_Primer_0x1)
- [Kernel Exploitation Primer 0x2 - SMEP & kASLR & VBS](https://ghostbyt3.github.io/blog/Kernel_Exploitation_Primer_0x2)
- [Kernel Exploitation Primer 0x3 - VBS & HVCI](https://ghostbyt3.github.io/blog/Kernel_Exploitation_Primer_0x3)
- [Kernel Exploitation Primer 0x4 - Type Confusion & Use-After-Free Vulnerabilities](https://ghostbyt3.github.io/blog/Kernel_Exploitation_Primer_0x4)
- [Kernel Exploitation Primer 0x5 - Arbitrary Write (Write-What-Where)](https://ghostbyt3.github.io/blog/Kernel_Exploitation_Primer_0x5)

## CTF Writeups

Explore solutions from various CTF competitions:

- [DownUnderCTF 2020](./CTFs/DownUnderCTF2020/)
- [HacktivityCon 2020](./CTFs/HacktivityCon_2020/)
- [DarkCon 2021](./CTFs/DarkCon2021/)
- [DiceCTF 2021](./CTFs/DiceCTF2021/)
- [SecurinetsCTF 2021](./CTFs/SecurinetsCTF2021/)
- [CyberApocalypse 2021](./CTFs/CyberApocalypse2021/)
- [NahamCon 2021](./CTFs/NahamCon2021/)
- [BlueHens 2021](./CTFs/BlueHens2021/)
- [3kCTF 2020](./CTFs/3kCTF2020/)
- [HTB RopeTwo](./CTFs/RopeTwo_HackTheBox/)

## Research Materials

Navigate to [Research/](./Research/) for deep dives into:

- [malloc() Internals](./Research/malloc.md)
- [free() Internals](./Research/free.md)
- [calloc() Internals](./Research/calloc.md)
- [realloc() Internals](./Research/realloc.md)
- [Hook Functions](./Research/hook_functions.md)
- [Tcache Mechanisms](./Research/tcache.md)
- [Stdout Functions](./Research/stdout_functions.md)
- [Overflow Techniques](./Research/overflow.md)

## Assembly Resources

Navigate to [Assembly/](./Assembly/) for:

- [Chapter 1: Assembly Fundamentals](./Assembly/Chapter-1.md)

## Debugging Guides

Navigate to [Debugging/](./Debugging/) for:

- [Chapter 1: Debugging Fundamentals](./Debugging/chapter-1.md)

## Challenges

Navigate to [Challenges/](./Challenges/) to test your skills:

- [Bit Flip Challenge](./Challenges/bit_flip.md)

## Getting Started

To get started with PwnLand:

1. Clone this repository:
   ```bash
   git clone https://github.com/PwnFuzz/PwnLand.git
   ```

2. Browse to a topic of interest in the repository.

3. Follow the tutorials and examples to enhance your skills.

4. For binary examples, navigate to the [binaries/](./binaries/) directory.

## Contributing

Contributions to PwnLand are welcome! Whether you want to fix a typo, add a tutorial, or contribute a CTF writeup, please follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -am 'Add new tutorial on XYZ'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Create a new Pull Request

Please ensure your contributions follow the existing structure and include appropriate documentation.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

---

<div align="center">
  <p>© 2025 PwnFuzz - Open Source R&D Lab for Fuzzing, Reverse Engineering, Vulnerability Research & Exploit Development</p>
</div>