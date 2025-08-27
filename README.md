
# 🕵‍♂ Stego-Darshan

A lightweight steganography tool for Linux that hides secret messages/files inside images with AES-256 encryption.
Built for Kali-style usage, it installs system-wide and works as a simple CLI tool.
## ✨ Features

- 🔒 AES-256 Encryption (via cryptography lib)

- 🖼 Supports PNG & JPG images

- 📝 Embed text messages or files(Image, Video, PDF)

- 🔑 Passkey-protected secrets

- 📤 Extract hidden data securely

- 🗜️ Option to compress the file 

- ⚡ Installs like a Linux tool 

- 🛠 Easy install & uninstall scripts
## 📦 Installation

Go to your Kali Terminal

```bash
git clone https://github.com/INDGAMING262/Steg-Darshan.git
cd Stego-Darshan
```

Run this cmd in that directory

```bash
sudo bash installer.sh
```

It available anyware(For that particular user) just type and run

```bash
stego-darshan
```
    
## 🖥 Usage
The tool has three main modes: ***embed, extract and info.***

`stego-darshan <command> [options]`


**Use:** _stego-darshan <mode> -h_

### 📝Create a Image with hidden text
```bash
stego-darshan embed -i <Image.jpeg> -t My Secret Text -o Steg_Image.jpeg 
```

It will ask:
```text
Passkey:
```
Then enter a password for your data, after it will genarate a Steg_Image.jpeg Image containig your hidden message.









## ⚙️Options

#### Use these commands



| **Commands**  |  **Name**    | **Description**                |
| :----------   | :-------     | :-------------------------     |
|  `-h, --help` | Help         | Show help message and exit     |
| ` -i, --in`   | INFILE        | Cover image (png/jpg
 `-o, --out` |OUTFILE   |Output stego PNG(default: stego_output.png)
  `-t, --text` |TEXT     |Secret text to embed
  `-f, --file` |FILE     |Secret file to embed(Image,Video,Pdf)
  `--compress` |Compress|Compress payload (gzip) before encryption
  `-p, --pass` |PASSKEY  |Passkey (will prompt if omitted)



### 🖼️ Extract data from Image
```bash
stego-darshan extract -i <Steg_Image.jpeg> 
```

It will ask:
```text
Passkey:
```
Then enter a password you enterd, after it will give your secret message/files.


## ⚙️Options

#### Use these commands

| **Commands**  |  **Name**    | **Description**                |
| :----------   | :-------     | :-------------------------     |
|  `-h, --help` | Help         | Show help message and exit     |
| ` -i, --in`   | STEGO        | Stego image (png)
|` -d, --outdir`| OUTDIR       |Directory to write extracted file(default: current directory)|
| `-p, --pass`    | PASSKEY      |Passkey (will prompt if omitted)|

### 🔍Use info mode

```bash
stego-darshan info -i Steg_Image.jpeg
```
It gives more information:
```text
Image: Steg_Image.jpeg  Size: (3000, 4000)  Capacity: 36000000 bits (4500000 bytes)
[+] Found embedded payload: type=1, encrypted_len=48 bytes

```
## ⚙ Dependencies

Installed automatically via **installer.sh:**

- python3

- python3-pil (Pillow for image processing)

- python3-cryptography (for AES encryption)
## 👨‍💻 Author

Darshan Rao

@indgamin_262 

## 📝 License

This project is licensed under the MIT License – free to use, modify, and distribute.
