#!/usr/bin/env python3

from __future__ import annotations
import struct
import argparse
import sys
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, Optional, Union, List, Any, Set, ClassVar

# pip install cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.backends import default_backend


logger = logging.getLogger("gsdf")


class PayloadType(IntEnum):
    OPERATIONAL_FIRMWARE = 0x1000
    RESCUE_FIRMWARE = 0x1001
    GUI = 0x1002
    PERMANENT_PARAMETERS = 0x1003
    BOOTLOADER = 0x1004
    UPDATE_FIRMWARE = 0x1005
    REFURBISH_FIRMWARE = 0x1006
    TEST_FIRMWARE = 0x1007
    ROOT_SECURITY_PARAMETERS = 0x1008
    ATTRIBUTE_CERTIFICATE = 0x1009

    def __str__(self) -> str:
        return self.name.lower().replace("_", " ")


class SectionType(IntEnum):
    ROOT_CERT = 0x2000
    SECOND_CERT = 0x2001
    ATTRCERT_RSPS = 0x2002
    PERM_PARAMS = 0x2003
    PRIM_BL_IMG = 0x2004
    SEC_BL_IMG = 0x2005
    UBOOT_IMG = 0x2006
    KERNEL_IMG = 0x2007
    SQUASHFS = 0x2008
    DTB = 0x2009
    PRIM_BL_ARGS = 0x2014
    SEC_BL_ARGS = 0x2015
    UBOOT_ARGS = 0x2016
    KERNEL_ARGS = 0x2017

    def __str__(self) -> str:
        return self.name.lower().replace("_", " ")

    @property
    def filename(self) -> str:
        return f"{self.name.lower()}.bin"


@dataclass
class GSDFHeader:
    size: int = 0
    payload_type: PayloadType = PayloadType.OPERATIONAL_FIRMWARE
    version: int = 1
    timestamp: Optional[int] = None
    name: str = ""

    MAGIC: ClassVar[bytes] = b"GSDF 10"
    FORMAT: ClassVar[str] = ">8sIIII8x64s"

    def __post_init__(self) -> None:
        if self.timestamp is None:
            self.timestamp = int(datetime.now().timestamp())

    @classmethod
    def from_bytes(cls, data: memoryview) -> GSDFHeader:
        if data[:len(cls.MAGIC)] != cls.MAGIC:
            raise ValueError("Invalid GSDF Magic")

        _, sz, p_type, ver, ts, name = struct.unpack_from(cls.FORMAT, data)

        if sz != len(data):
            raise ValueError(f"Size mismatch: Header says {sz}, file is {len(data)}")

        return cls(sz, PayloadType(p_type), ver, ts, name.decode("ascii", errors="ignore"))

    def to_bytes(self) -> bytes:
        return struct.pack(
            self.FORMAT, 
            self.MAGIC, 
            self.size,
            self.payload_type.value,
            self.version,
            self.timestamp,
            self.name.encode("ascii")[:63]
        )

@dataclass
class GSDFSection:
    type_id: SectionType
    data: bytes
    offset: int = 0

    FORMAT: ClassVar[str] = ">III4x"
    
    @property
    def size(self) -> int:
        return len(self.data)

    @classmethod
    def from_bytes(cls, data: memoryview, offset: int = 0x60) -> Optional[GSDFSection]:
        s_type, s_offset, s_size = struct.unpack_from(cls.FORMAT, data, offset)
        if s_type == 0:
            return None

        return cls(SectionType(s_type), data[s_offset:s_offset+s_size].tobytes(), s_offset)

    def to_bytes(self) -> bytes:
        return struct.pack(self.FORMAT, self.type_id.value, self.offset, self.size)


class ValidationError(Exception):
    pass


class GSDFArchive:
    # From libgsdf.so.1.0.0
    TRUSTED_CAS: Dict[str, str] = {
        "1263a2056501171b5e0ba777b0894d1655ddf621a38ebc8da96159122a1ba2dd": "Sagemcom caCert",
        "4c1501be33c5bd93e5b0dada2b32bcdcf695154b87890a7feb29fa68b50331a1": "Telstra GTW Devices Sign Firmware CA",
        "27707c8e81f9989d8aed361189e04bf04283dd478cc1d6eb8016dc1d4e3a1ff1": "Teo GTW Devices Sign Firmware CA",
        "d0e0686f1c53a7edf5a81252b6506690c3c5e3db7ce3348ae0369e5075d7992d": "orange CA_FT_PKI_FW",
        "b33a7d3899ed483bc04d8364867839a6b527ad551e5757082e6ced72d4353bfa": "orange CA_FT_PKI_WebGUI",
        "23267429955a2d2a063d34c1d92a7e81d712c34e0a67d25413001e1a4274257f": "SAGEMCOM GTW Devices Sign Firmwar CA"
    }

    # From libgsdf.so.1.0.0
    REQUIRED_MASKS: List[int] = [0x800181, 0x800181, 0x101, 0x9, 0x1, 0x800081, 0x800081, 0x800081, 0x5, 0x5]
    ALLOWED_MASKS: List[int] = [0x202, 0x202, 0x2, 0x2, 0x700072, 0x202, 0x202, 0x202, 0x2, 0x2]

    def __init__(self, data: Optional[bytes] = None, payload_type: PayloadType = PayloadType.OPERATIONAL_FIRMWARE) -> None:
        self.sections: Dict[SectionType, GSDFSection] = {}
        self.raw_data: Optional[memoryview] = None

        if data:
            self.raw_data = memoryview(data)
            self._load()
        else:
            self.header = GSDFHeader(payload_type=payload_type)

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> GSDFArchive:
        file_path = Path(path)
        try:
            return cls(file_path.read_bytes())
        except FileNotFoundError:
            raise FileNotFoundError(f"Path does not exist: {path}")
        except PermissionError:
            raise PermissionError(f"Permission denied when reading: {path}")

    @classmethod
    def from_url(cls, url: str) -> GSDFArchive:
        import urllib.request
        import urllib.error
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                return cls(response.read())
        except urllib.error.HTTPError as e:
            raise ConnectionError(f"HTTP Error {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            raise ConnectionError(f"Network unreachable: {e.reason}")

    @classmethod
    def from_stdin(cls) -> GSDFArchive:
        return cls(sys.stdin.buffer.read())

    @classmethod
    def from_stream(cls, source: str, **kwargs) -> GSDFArchive:
        if source == "-":
            return cls.from_stdin(**kwargs)
        if source.startswith(("http://", "https://")):
            return cls.from_url(source, **kwargs)
        return cls.from_file(source, **kwargs)

    @classmethod
    def get_requirements(cls, p_type: PayloadType) -> Dict[str, List[SectionType]]:
        p_base = next(iter(PayloadType)).value
        s_base = next(iter(SectionType)).value
        idx = p_type.value - p_base

        req_mask = cls.REQUIRED_MASKS[idx] if 0 <= idx < len(cls.REQUIRED_MASKS) else 0
        all_mask = cls.ALLOWED_MASKS[idx] if 0 <= idx < len(cls.ALLOWED_MASKS) else 0

        def mask_to_list(mask):
            return [SectionType(s_base + i) for i in range(32) if (mask & (1 << i))]

        return {"required": mask_to_list(req_mask), "optional": mask_to_list(all_mask)}

    def __len__(self) -> int:
        return len(self.sections)

    def __iter__(self):
        return iter(sorted(self.sections.keys(), key=lambda k: self.sections[k].offset))

    def __getitem__(self, key: Union[SectionType, int, slice]) -> Union[GSDFSection, List[GSDFSection]]:
        if isinstance(key, SectionType):
            return self.sections[key]

        ordered_sections = sorted(self.sections.values(), key=lambda s: s.offset)

        if isinstance(key, (int, slice)):
            return ordered_sections[key]

        raise TypeError(f"Invalid index type: {type(key)}")

    def _load(self) -> None:
        mv: Optional[memoryview] = self.raw_data
        if mv is None: return

        self.header = GSDFHeader.from_bytes(mv)

        for i in range(16):
            sec = GSDFSection.from_bytes(mv, 0x60 + (i * struct.calcsize(GSDFSection.FORMAT)))
            if sec is not None:
                self.sections[sec.type_id] = sec

        logger.info("ident string OK")
        logger.info("size OK")

    def verify(self) -> None:
        mv: Optional[memoryview] = self.raw_data
        if mv is None: raise ValidationError("No data loaded")
 
        # Section Table Validation
        reqs = self.get_requirements(self.header.payload_type)

        # Required Check
        for req in reqs["required"]:
            if req not in self.sections:
                raise ValidationError(f"Missing required section: {str(req)} ({hex(req)})")

        # Prohibited Check
        allowed = set(reqs["required"]) | set(reqs["optional"])
        for k in self.sections:
            if k not in allowed:
                raise ValidationError(f"Prohibited section {str(k)} ({hex(k)}) found")

        logger.info("payload requirements OK")

        # Crypto Integrity (Hashes 1, 2, and 3)
        if hashlib.sha256(mv[:0x160]).digest() != mv[0x160:0x180]:
            raise ValidationError("Header hash mismatch")
        logger.info("header hash OK")

        if hashlib.sha256(mv[0x2C0:]).digest() != mv[0x1A0:0x1C0]:
            raise ValidationError("Payload data hash mismatch")
        logger.info("data hash OK")

        auth_block = bytearray(mv[0x160:0x2C0])
        auth_block[0x20:0x40] = b"\x00" * 32
        auth_block[0x60:0x160] = b"\x00" * 256
        if hashlib.sha256(auth_block).digest() != mv[0x180:0x1A0]:
            raise ValidationError("Auth block hash mismatch")
        logger.info("authentication hash OK")

        # Root Trust Verification
        if SectionType.ROOT_CERT not in self.sections:
            raise ValidationError("Root certificate section missing.")

        raw_cert = self.sections[SectionType.ROOT_CERT].data
        normalized_cert = bytes([b for b in raw_cert if b not in (0x0D, 0x0A)])
        root_hash = hashlib.sha256(normalized_cert).hexdigest()

        if root_hash not in self.TRUSTED_CAS:
            raise ValidationError(f"untrusted root certificate: {root_hash}")
        logger.info(f"root certificate OK ({self.TRUSTED_CAS[root_hash]})")

        # Chain & Signature Verification
        try:
            root_c = x509.load_pem_x509_certificate(raw_cert, default_backend())
            sign_c = root_c
            logger.debug("found a root CA certificate in section 0")

            if SectionType.SECOND_CERT in self.sections:
                logger.debug("found a secondary certificate in section 1")
                sec_c = x509.load_pem_x509_certificate(self.sections[SectionType.SECOND_CERT].data, default_backend())
                root_c.public_key().verify(
                    sec_c.signature, sec_c.tbs_certificate_bytes,
                    padding.PKCS1v15(), sec_c.signature_hash_algorithm
                )
                sign_c = sec_c

            logger.info("certificate chain OK")
            logger.info("certificate revocation list verification *TBI*")

            # Verify signature against the pre-calculated Hash 2 at 0x180
            sign_c.public_key().verify(
                mv[0x1C0:0x2C0].tobytes(),
                mv[0x180:0x1A0].tobytes(),
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA256())
            )
            logger.info("certificate signature OK")
        except Exception as e:
            raise ValidationError(f"Signature or Chain verification failed: {str(e)}")

    def extract(self, output_dir: Union[str, Path]) -> None:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        logger.info(f"extracting {len(self.sections)} sections to {out_path.resolve()}")

        for s_type in self:
            sec = self[s_type]
            dest = out_path / s_type.filename
            dest.write_bytes(sec.data)
            logger.debug(f"unpacked {str(s_type)} to {str(dest)} ({sec.size} bytes)")

    def create(self, output_path: str, sources: List[Path], key_path: Optional[Path] = None) -> None:
        self.sections.clear()

        # Map available files to SectionTypes
        available_files: Dict[SectionType, Path] = {}

        for src in sources:
            if src.is_dir():
                for s_type in SectionType:
                    file_path = src / s_type.filename
                    if file_path.exists():
                        available_files[s_type] = file_path
            elif src.is_file():
                stem = src.name.lower().removesuffix(".bin").upper()
                try:
                    s_type = SectionType[stem]
                    available_files[s_type] = src
                except KeyError:
                    logger.warning(f"skipping unrecognized file {src.name}")

        # Validate against requirements
        reqs = self.get_requirements(self.payload_type)
        allowed = set(reqs["required"]) | set(reqs["optional"])

        for s_type, file_path in available_files.items():
            if s_type in allowed:
                self.sections[s_type] = GSDFSection(s_type, file_path.read_bytes())
                logger.debug(f"packed {s_type.name} from {file_path.name}")
            else:
                logger.warning(f"{s_type.name} is not allowed for {self.payload_type.name}. skipping.")

        # Check for missing required sections
        for req in reqs["required"]:
            if req not in self.sections:
                raise ValidationError(f"Missing required section: {str(req)}")

        # Sort and calculate offsets
        sorted_keys = sorted(self.sections.keys())
        payload = b"".join(self.sections[k].data for k in sorted_keys)

        meta = bytearray(0x2E0)
        # Padding
        meta[0x2C0:0x2E0] = b"\xFF" * 32

        offset = len(meta)

        # Section Table
        for i, k in enumerate(sorted_keys):
            self.sections[k].offset = offset
            meta[0x60+(i*16):0x60+(i+1)*16] = self.sections[k].to_bytes()
            offset += self.sections[k].size

        # Header
        self.header.size = offset
        meta[0:0x60] = self.header.to_bytes()

        # Hashes & Signature
        meta[0x1A0:0x1C0] = hashlib.sha256(payload).digest()
        meta[0x160:0x180] = hashlib.sha256(meta[:0x160]).digest()
        meta[0x180:0x1A0] = hashlib.sha256(meta[0x160:0x2C0]).digest()

        if key_path:
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            meta[0x1C0:0x2C0] = key.sign(meta[0x180:0x1A0], padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))

        Path(output_path).write_bytes(meta + payload)
        logger.info(f"gsdf created OK ({output_path})")

    def report(self, file=sys.stdout) -> None:
        lines = [
            "=" * 100,
            f"GSDF ARCHIVE:",
            "=" * 100,
            f"{'Name:':<15} {self.header.name}",
            f"{'Payload Type:':<15} {str(self.header.payload_type).title()} ({hex(self.header.payload_type.value)})",
            f"{'Version:':<15} {self.header.version}",
            f"{'Timestamp:':<15} {datetime.fromtimestamp(self.header.timestamp)}",
            f"{'Total Size:':<15} {self.header.size} bytes",
            "=" * 100,
            f"SECTIONS:",
            "=" * 100,
            f"{'Type':<15} {'Offset':<10} {'Size (Bytes)':<15} Data (Preview)",
            "-" * 100
        ]

        for s_type in self:
            sec = self[s_type]
            if s_type in (SectionType.ROOT_CERT, SectionType.SECOND_CERT):
                preview = sec.data[:45].decode("ascii", errors="ignore").replace("\n", "<CR>")
            else:
                preview = sec.data[:16].hex(" ")

            lines.append(f"{str(s_type):<15} {hex(sec.offset):<10} {sec.size:<15} {preview}")

        print("\n".join(lines), file=file)


class ListPayloadsAction(argparse.Action):
    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        print(f"{'ID':<6} {'Payload Type':<25} {'Requirements'}")
        print("-" * 100)

        for p in PayloadType:
            reqs = GSDFArchive.get_requirements(p)
            req_str = ", ".join(str(r) for r in reqs["required"])
            opt_str = f" (optional: {", ".join(str(s) for s in reqs['optional'])})" if reqs["optional"] else ""
            print(f"{hex(p.value):<6} {str(p).title():<25} {req_str}{opt_str}")

        parser.exit()


def main() -> None:
    parser = argparse.ArgumentParser(description="GSDF Tool")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")

    parser.add_argument("--list-payloads", action=ListPayloadsAction, 
                        help="Show payload requirements")

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_read = subparsers.add_parser("read", help="Verify or extract an existing archive")
    p_read.add_argument("source", help="Path, URL, or '-' for stdin")
    p_read.add_argument("-e", "--extract", metavar="DIR", help="Directory to extract to")

    p_create = subparsers.add_parser("create", help="Create a new archive from files")
    p_create.add_argument("output", help="The filename to create")
    p_create.add_argument("source", nargs="+", help="Directory or list of .bin files to pack")
    p_create.add_argument("-k", "--key", type=Path, help="Private key for signing")
    p_create.add_argument("-p", "--payload", type=lambda x: PayloadType[x.upper().replace(" ", "_")], 
                         default=PayloadType.OPERATIONAL_FIRMWARE,
                         help="Payload type (--list-payloads)")

    args = parser.parse_args()

    match args.verbose:
        case 0: level = logging.WARNING
        case 1: level = logging.INFO
        case _: level = logging.DEBUG

    logging.basicConfig(level=level, format="%(levelname)s: GSDF %(message)s", stream=sys.stderr)

    try:
        if args.command == "read":
            gsdf = GSDFArchive.from_stream(args.source)
            gsdf.verify()
            logger.info(f"gsdf file {args.source} is valid")
            gsdf.report()
            if args.extract:
                gsdf.extract(args.extract)
        elif args.command == "create":
            gsdf = GSDFArchive(payload_type=args.payload)
            source_paths = [Path(s) for s in args.source]
            gsdf.create(args.output, sources=source_paths, key_path=args.key)
    except (ValidationError, ConnectionError, FileNotFoundError) as e:
        logger.error(f"{e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
