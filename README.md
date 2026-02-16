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
