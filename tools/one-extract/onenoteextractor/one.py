# OneNoteExtractor
# Copyright (C) 2023 Volexity, Inc.

"""Quick extractor for OneNote files, allowing for programmatic extraction of subfiles."""

# builtins
from datetime import datetime, timedelta
import base64
import logging
from io import BytesIO
import json
import re
import struct
import traceback
from typing import Iterator
from xml.dom.minidom import parseString

# installables
from msoffcrypto.method.ecma376_agile import ECMA376Agile

# locals
from .enc import decrypt

EMBEDDED_FILE_MAGIC = b"\xe7\x16\xe3\xbd\x65\x26\x11\x45\xa4\xc4\x8d\x4d\x0b\x7a\x9e\xac"  # noqa E501
TITLE_MAGIC = b"\xf3\x1c\x00\x1c\x30\x1c\x00\x1c\xff\x1d\x00\x14\x82\x1d\x00\x14"  # noqa E501
HEADER = b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3"
ENC_ONENOTE_MARKER = b"http://schemas.microsoft.com/office/2006/keyEncryptor/password"

# Files used for testing
# 93fb9f37eb70c095e26cedc594ca55ab27710039d0f4e92878e6539975ae58aa
# c9098f9680174838236499bcbee0cf8b6ebd900bdd4cfa6045d0c2ee91f5f81a
# 28ceae52efb536176dfcabb931ff84551dec9bfa3285a6b54cd33e36b7855c5b
# 5b8de945d22780ef5c0dcdb40848f47515601d3be4f1fe1ac541375d187c3832
# e0d9f2a72d64108a93e0cfd8066c04ed8eabe2ed43b80b3f589b9b21e7f9a488
# 3f00a56cbf9a0e59309f395a6a0b3457c7675a657b3e091d1a9440bd17963f59
# 9bf99fc32dc69f213812c3c747e8dd41fef63ad0fd0aec01a6b399aeb10a166a
# 73e77e4f5d51ea67cb63539260741b703f0ea9a40782611eb005b5df804865dc
# b6d84f95fb91c71dbc66377d995ef5ccccd94880afc5d8dd678e9672c44a76f0
# a748f4e526c1a5fed7e57887ef951e451236ee3ad39cf6161d18e5c2230aca0b
# 222b1a425f75fc7998a0bbabd52277cd82bb5ec50b75f4fb67568b3b754f5406
# 7d51b0f696ad7c3d92fe0485052aebacca367d64f37aebd446fdf613b4719024
# 2283c3be89eb6cbf0e1579a6e398a5d1f81a50793fcca22fbc6cbdab53dc2d31
# b13c979dae8236f1e7f322712b774cedb05850c989fc08312a348e2385ed1b21
# cf9525d9589671d35a4ab7c8cfccc74fb2b974d506e1e00f4ee46840b4e6d6dd
# eb674dc2e3787de0948e0af5a50aa365b21eb2dd40c0ef9034e44ed1c46b11d1

logger = logging.getLogger(__name__)

class OneNoteExtractorException(Exception):
    """Custom exception handler for OneNoteExtractor."""

    pass


class OneNoteMetadataObject(object):
    """Object to represent OneNoteMetadata components."""

    def __init__(self,
                 object_id: int,
                 offset: int,
                 title_size: int,
                 title: str,
                 creation_date: datetime,
                 last_modification_date: datetime) -> None:
        self.object_id = object_id
        self.title_size = title_size
        self.offset = offset
        self.title = title
        self.creation_date = creation_date
        self.last_modification_date = last_modification_date

    def __repr__(self) -> str:
        """Print JSON repr of this object."""
        j = self.to_dict()
        return json.dumps(j, sort_keys=True, indent=4)

    def to_dict(self) -> dict:
        """Return a dictionary representation of a metadata object."""
        r = {}
        for k, v in self.__dict__.items():
            if isinstance(v, datetime):
                v = v.strftime('%Y-%m-%dT%H:%M:%SZ')
            r[k] = v
        return r


class OneNoteExtractor:
    """Simple OneNoteExtractor class to assist in extraction of embedded files."""

    def __init__(self,
                 data: bytes,
                 password: str = None) -> None:
        """Init a OneNoteExtractor object.

        :param data: file data from a .one file

        :raises OneNoteExtractorException: when data doesn't match known .one file format
        """
        self.data = data
        self.enc_info = None
        self.is_valid = self._is_valid()
        if self.is_valid is False:
            raise OneNoteExtractorException("Invalid OneNote file encountered")
        if self._is_password_protected():
            if not password:
                raise OneNoteExtractorException("PasswordProtected OneNote file encountered but no"
                                                " password was supplied.")
            self.enc_info = self.derive_enc_info(password)

    def _is_valid(self) -> bool:
        """Check if the first 16 bytes in `self.data` match known OneNote file header structure."""
        if self.data[0:16] == HEADER:
            return True
        else:
            return False

    def _is_password_protected(self) -> bool:
        """Check the first megabyte of data for indicators that the file is password protected.

        Returns:
            bool: _description_
        """
        # !TODO - this is a brittle check that probably could be improved.
        if ENC_ONENOTE_MARKER in self.data[0:1000000]:
            return True
        return False

    def _get_time(self, date: bytes) -> datetime:
        """Convert byte representation of datetime to python datetime object.

        Args:
            date (bytes): Bytes to convert

        Returns:
            datetime: Converted datetime.
        """
        i_value = struct.unpack("<Q", bytearray(date))[0]
        h_value = datetime(1601, 1, 1) + timedelta(microseconds=i_value / 10)
        return h_value

    def _decrypt_embedded_object(self, blob: bytes):
        """Decrypt an embedded object `blob` using self.enc_info."""
        # If this is called enc_info should be populated, but we'll check just incase.
        if not self.enc_info:
            raise OneNoteExtractorException("Unreachable code reached")
        buf = BytesIO(blob)
        obuf = decrypt(key=self.enc_info['secret_key'],
                       keyDataSalt=self.enc_info["keyDataSalt"],
                       hashAlgorithm=self.enc_info["keyDataHashAlgorithm"],
                       ibuf=buf)
        return obuf[8:]

    def derive_enc_info(self,
                        password: str) -> dict:
        """Derive the encryption info required to decrypt embedded objects.

        Args:
            password (str): The password used to encrypt the notebook.

        Returns:
            dict: A dictionary containing data required to decrypt embedded objects.
                 Structure is:
                    {'secret_key': '',
                     'keyDataSalt': '',
                     'keyDataHasAlgorithm': ''}
        """
        # Find the XML blob containing encryption parameters
        match = re.search(pattern=b"<encryption xmlns=.*</encryption>", string=self.data)
        enc_config = match.group()

        # Parse the blob and read key parameters
        xml = parseString(enc_config)
        keyData = xml.getElementsByTagName("keyData")[0]
        keyDataSalt = base64.b64decode(keyData.getAttribute("saltValue"))
        keyDataHashAlgorithm = keyData.getAttribute("hashAlgorithm")

        password_node = xml.getElementsByTagNameNS("http://schemas.microsoft.com/office/2006/keyEncryptor/password", "encryptedKey")[0]  # noqa:E501
        spinValue = int(password_node.getAttribute("spinCount"))
        encryptedKeyValue = base64.b64decode(password_node.getAttribute("encryptedKeyValue"))
        encryptedVerifierHashInput = base64.b64decode(password_node.getAttribute("encryptedVerifierHashInput"))  # noqa:E501
        encryptedVerifierHashValue = base64.b64decode(password_node.getAttribute("encryptedVerifierHashValue"))  # noqa:E501
        passwordSalt = base64.b64decode(password_node.getAttribute("saltValue"))
        passwordHashAlgorithm = password_node.getAttribute("hashAlgorithm")
        passwordKeyBits = int(password_node.getAttribute("keyBits"))

        verified = ECMA376Agile.verify_password(
            password,
            passwordSalt,
            passwordHashAlgorithm,
            encryptedVerifierHashInput,
            encryptedVerifierHashValue,
            spinValue,
            passwordKeyBits,
        )
        if verified:
            secret_key = ECMA376Agile.makekey_from_password(
                password,
                passwordSalt,
                passwordHashAlgorithm,
                encryptedKeyValue,
                spinValue,
                passwordKeyBits,
            )
            return {
                'secret_key': secret_key,
                'keyDataSalt': keyDataSalt,
                'keyDataHashAlgorithm': keyDataHashAlgorithm,
            }
        raise OneNoteExtractorException("Decryption didn't work - wrong password supplied? "
                                        f"Supplied password was: {password}")

    def extract_files(self) -> Iterator[bytes]:
        """Find embedded objects in .one files.

        Returns an iterator containing those objects.
        """
        if self.is_valid is False:
            logger.error("Cannot extract files - header is invalid.")
            return False

        match = re.finditer(EMBEDDED_FILE_MAGIC, self.data, re.DOTALL)
        if match:
            try:
                counter = 0
                for m in match:
                    counter += 1
                    size_offset = m.start() + 16
                    size = self.data[size_offset:size_offset + 4]
                    size_bytes = bytearray(size)
                    i_size = struct.unpack("<I", size_bytes)[0]
                    blob = self.data[m.start() + 36: m.start() + 36 + i_size]
                    if self.enc_info:
                        # msoffcrypto-tool expects the blob to be of format
                        # [4 bytes of size] [4 unknown bytes] [ data]
                        # but the format in .one files is different, so we artificially
                        # create a similar structure here.
                        logger.debug("Decrypting embedded object")
                        yield self._decrypt_embedded_object(size_bytes + b"\x00\x00\x00\x00" + blob)
                    else:
                        yield blob
                logger.debug(f"{counter} files extracted.")
                return
            except Exception as e:
                logger.error(f"Error while parsing the file: {e}.")
                if logger.getEffectiveLevel() == logging.DEBUG:
                    traceback.print_exc()
                return
        else:
            logger.debug("No embedded files found.")
            return

    def extract_meta(self) -> Iterator[OneNoteMetadataObject]:
        """Extract metadata from embedded objects in .one files.

        Returns an iterator containing those objects.
        """
        if self.enc_info:
            logger.error("Unable to extract metadata from encrypted .one files.")
            return []
        match = re.finditer(TITLE_MAGIC, self.data, re.DOTALL)
        ret = []
        if match:
            for index, m in enumerate(match):
                try:
                    offset = m.start() - 4
                    adjust = self.data[offset + 2:offset + 4]
                    i_adjustment = struct.unpack("<H", bytearray(adjust))[0]
                    size_offset = offset + 4 + (4 * i_adjustment)
                    size = self.data[size_offset:size_offset + 4]
                    i_size = struct.unpack("<I", bytearray(size))[0]
                    logger.debug(f"title offset: {size_offset}")
                    title_str = self.data[size_offset + 4:size_offset + 4 + i_size].decode()
                    creatDate_offset = size_offset + 4 + i_size + 32
                    creatDate = self.data[creatDate_offset:creatDate_offset + 8]
                    h_createDate = self._get_time(creatDate)
                    cpt = creatDate_offset + 16
                    valid = False
                    while cpt < creatDate_offset + 100:
                        if self.data[cpt:cpt + 6] == b"\x01\x01\x00\x00\x00\x00":
                            valid = True
                            break
                        if self.data[cpt:cpt + 6] == b"\x01\x00\x00\x00\x00\x00":
                            valid = True
                            break
                        cpt = cpt + 1
                    if valid:
                        LastDate_offset = cpt - 7
                        LastDate = self.data[LastDate_offset:LastDate_offset + 8]
                    else:
                        LastDate = None
                    h_LastDate = None
                    if LastDate:
                        h_LastDate = self._get_time(LastDate)
                    yield OneNoteMetadataObject(object_id=index,
                                                offset=offset,
                                                title_size=i_size,
                                                title=title_str.replace("\x00", ""),
                                                creation_date=h_createDate,
                                                last_modification_date=h_LastDate)

                except Exception as e:
                    logger.error(f"Error while parsing object {cpt}")
                    logger.error(f"Error: {e}.")
        return ret
