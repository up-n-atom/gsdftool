# gsdftool.py

Sagemcom GSDF Tool

## Quickstart

### List payload types and requirements

``` sh
python gsdftool.py --list-payloads
```

### Inspect and verify

``` sh
python gsdftool.py read file.gsdf
```

### Extract all sections

``` sh
python gsdftool.py read file.gsdf --extract ./files
```

### Process extracted sections
``` sh
python gsdftool.py read file.gsdf --extract ./files --process
```

### Remote inspection

``` sh
python gsdftool.py read https://example.com/path/to/file.gsdf
```

### Create new GSDF

``` sh
python gsdftool.py create file.gsdf ./files --payload test_firmware --key private_key.pem
```

## Command reference

``` sh
usage: gsdftool.py [-h] [-v] [--list-payloads] {read,create} ...

GSDF Tool

positional arguments:
  {read,create}
    read           Verify or extract an existing archive
    create         Create a new archive from files

options:
  -h, --help       show this help message and exit
  -v, --verbose    Increase verbosity (-v, -vv)
  --list-payloads  Show payload requirements
```
### `read` command

``` sh
usage: gsdftool.py read [-h] [-e DIR] source

positional arguments:
  source             Path, URL, or '-' for stdin

options:
  -h, --help         show this help message and exit
  -e, --extract DIR  Directory to extract to
  --process          Auto-process known payloads
```

### `create` command

``` sh
usage: gsdftool.py create [-h] [-k KEY] [-p PAYLOAD] output source [source ...]

positional arguments:
  output                The filename to create
  source                Directory or list of .bin files to pack

options:
  -h, --help            show this help message and exit
  -k, --key KEY         Private key for signing
  -p, --payload PAYLOAD
                        Payload type (--list-payloads)
```

#### Supported payloads

> [!NOTE]
> Payload source files use the section_name.bin format, e.g. `kernel_img.bin`

| Payload                  | Mandatory Section/File(s)                    | Optional Section/File(s)                                                               |
| ------------------------ | -------------------------------------------- | -------------------------------------------------------------------------------------- |
| Operational Firmware     | root cert, kernel img, squashfs, kernel args | second cert, dtb                                                                       |
| Rescue Firmware          | root cert, kernel img, squashfs, kernel args | second cert, dtb                                                                       |
| Gui                      | root cert, squashfs                          | second cert                                                                            |
| Permanent Parameters     | root cert, perm params                       | second cert                                                                            |
| Bootloader               | root cert                                    | second cert, prim bl img, sec bl img, uboot img, prim bl args, sec bl args, uboot args |
| Update Firmware          | root cert, kernel img, kernel args           | second cert, dtb                                                                       |
| Refurbish Firmware       | root cert, kernel img, kernel args           | second cert, dtb                                                                       |
| Test Firmware            | root cert, kernel img, kernel args           | second cert, dtb                                                                       |
| Root Security Parameters | root cert, attrcert rsps                     | second cert                                                                            |
| Attribute Certificate    | root cert, attrcert rsps                     | second cert                                                                            |

### Verbosity levels

Outputs to `stderr`

| Type    | Level | 
| ------- | ----- |
| WARNING |       |
| INFO    | `-v`  |
| DEBUG   | `-vv` |

``` sh
python gsdftool.py -vv read file.gsdf --extract ./files
```

### Extra processors

The following payload sections can be further extracted:

* kernel img
* squashfs
* dtb

#### Debian/Ubuntu package requirements

``` sh
apt install -y squashfs-tools device-tree-compiler u-boot-tools gzip bzip2 lzma lzop lz4 zstd
```

#### Fedora/RedHat package requirements

``` sh
dnf -y install squashfs-tools dtc uboot-tools gzip bzip2 xz-lzma-compat lzop lz4 zstd
```

## File format

### Layout

| Offset | Size (Bytes) | Field            | Description                                                                 |
| ------ | ------------ | ---------------- | --------------------------------------------------------------------------- |
| 0x00   | 8            | Magic            | Fixed ASCII: `GSDF 10`                                                      |
| 0x08   | 4            | Total File Size  | Full size of the archive in bytes                                           |
| 0x0C   | 4            | Payload Type     | Identifies the firmware type                                                |
| 0x10   | 4            | Version          | Format version                                                              |
| 0x14   | 4            | Timestamp        | Unix epoch of creation time                                                 |
| 0x20   | 64           | Name             | Null-terminated ASCII string                                                |
| 0x60   | 256          | Section Table    | Up to 16 section descriptors (16 bytes each)                                |
| 0x160  | 32           | Integrity Hash 2 | SHA256 of the Header + Section Table (0x00 to 0x160)                        |
| 0x180  | 32           | Integrity Hash 1 | SHA256 of the Integrity Block (0x160 to 0x2C0 with Hash 3/Signature zeroed) |
| 0x1A0  | 32           | Integrity Hash 3 | SHA256 of the Payload Data (0x2C0 to EOF)                                   |
| 0x1C0  | 256          | Signature        | RSA-256 PKCS#1 v1.5 signature of Integrity Hash 2                           | 
| 0x2C0  | EOF          | Payload Data     | Concatenated raw binary data for all sections                               |

### Section Descriptor (starting at 0x60, 16 descriptors)

| Size (Bytes) | Field       | Description                                                |
| ------------ | ----------- | ---------------------------------------------------------- |
| 4            | Type ID     | The Section Type enum value                                |
| 4            | Data Offset | Absolute offset in the file where this section data begins |
| 4            | Data Size   | Size of the raw data in bytes                              |
| 4            | Padding     | Reserved for alignment                                     |


## To-do

- [ ] Evaluate external dependencies
  - [ ] uboot-tols -> [pyUboot](https://github.com/molejar/pyUBoot)
  - [ ] squashfs-tools -> [PySquashfsImage](https://github.com/matteomattei/PySquashfsImage)
  - [ ] gzip -> `import zlib`
  - [ ] bzip2 -> `import lzo`
  - [ ] lzma -> `import lzma`
  - [ ] lzo -> `import lzo`
  - [ ] lz4 -> `import lz4`
  - [ ] zstd -> `import zstandard`
  
