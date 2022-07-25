import asyncio
import serial_asyncio
import time
import struct
import binascii
import logging
import logging.handlers
import sys
import json

from enum import Enum


class DecodeState(Enum):
    UNKNOWN = 1
    DELIMITER_SEEN = 2
    DISTANCE_REPORT_FOLLOWS = 3
    REPLY_LENGTH_FOLLOWS = 4
    PAYLOAD_FOLLOWS = 5
    CHECKSUM_FOLLOWS = 6


class FrameType(Enum):
    NONE = 1
    DISTANCE_REPORT = 2
    REPLY = 3


FRAME_LEN = 9
FRAME_DELIM = 0x59
FRAME_CMD = 0x5A  # command and reply designator

open_retry = 5  # seconds
chunk_delay = 0.5  # seconds

port = "/dev/tf03"
speed = 115200
framerate = 3  # per sec
frames = 0
errored = 0
beyond_range = 0

MAX_DISTANCE = 18000


class DecodeState(Enum):
    UNKNOWN = 1
    DELIMITER_SEEN = 2
    DISTANCE_REPORT_FOLLOWS = 3
    REPLY_LENGTH_FOLLOWS = 4
    PAYLOAD_FOLLOWS = 5
    CHECKSUM_FOLLOWS = 6


class InputChunkProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        logger.debug(f"port opened {transport.serial.port}")
        self.transport = transport
        self.trace = False
        self.frame = bytearray()
        self.reset_decoder()
        # self.resume_reading()
        # transport.serial.rts = False  # You can manipulate Serial object via transport
        # transport.write(b'Hello, World!\n')  # Write serial data via transport

    def connection_lost(self, exc):
        logger.debug(f"---> connection_lost {exc}")
        self.pause_reading()
        # self.transport.loop.stop()

    def data_received(self, data):
        # logger.debug(f"data received {repr(data)}")

        for c in data:
            self.decode(c)
        # stop callbacks again immediately
        # self.pause_reading()

    def pause_reading(self):
        # This will stop the callbacks to data_received
        # logger.debug("---> pause_reading")
        self.transport.pause_reading()

    def resume_reading(self):
        # This will start the callbacks to data_received again with all data that has been received in the meantime.
        # logger.debug("---> resume_reading")
        self.transport.resume_reading()

    def pause_writing(self):
        logger.debug("---> pause_writing")

    def send_command(self, cmd, addchksum=False, comment=""):
        frame = bytearray.fromhex(cmd.replace(" ", ""))
        if addchksum:
            chkSum = 0
            for i in range(len(frame)):
                chkSum += frame[i]
            frame.append(int(chkSum & 0xFF))
        logger.debug(f"send_command: {binascii.hexlify(frame)}   {comment}")
        self.transport.write(frame)

    def reset_decoder(self):
        self.dstate = DecodeState.UNKNOWN
        self.frame.clear()
        self.frame_type = FrameType.NONE
        self.togo = 0

    def decode(self, c):
        global frames, errored

        self.frame.append(c)

        if self.dstate == DecodeState.UNKNOWN:
            if c == FRAME_DELIM:
                self.dstate = DecodeState.DELIMITER_SEEN
                return
            if c == FRAME_CMD:
                self.dstate = DecodeState.REPLY_LENGTH_FOLLOWS
                return

        if self.dstate == DecodeState.DELIMITER_SEEN:
            if c == FRAME_DELIM:
                self.frame_type = FrameType.DISTANCE_REPORT
                self.dstate = DecodeState.PAYLOAD_FOLLOWS
                self.togo = 5
                if self.trace:
                    logger.debug(f"DISTANCE: expect {self.togo}")
            return

        if self.dstate == DecodeState.REPLY_LENGTH_FOLLOWS:
            self.frame_type = FrameType.REPLY
            self.togo = int(c) - 4
            # logger.debug(f"REPLY: expect {self.togo}")
            self.dstate = DecodeState.PAYLOAD_FOLLOWS
            return

        if self.dstate == DecodeState.PAYLOAD_FOLLOWS:
            if self.togo > 0:
                if self.trace:
                    logger.debug(f"togo={self.togo} payload {c:02x}")
                self.togo -= 1
            else:
                # logger.debug("payload done")
                self.dstate = DecodeState.CHECKSUM_FOLLOWS
            return

        if self.dstate == DecodeState.CHECKSUM_FOLLOWS:
            chkSum = 0
            if self.trace:
                logger.debug(f"chksum  {len(self.frame)=} ")
            for i in range(len(self.frame) - 1):
                chkSum += self.frame[i]
                chkSum &= 0x00FF
            cksum_ok = (chkSum & 0xFF) == c
            if cksum_ok:
                frames += 1
                self.process()
            else:
                if self.trace:
                    logger.debug(
                        f"{self.frame_type=} {len(self.frame)=} {binascii.hexlify(self.frame)}"
                        f" {cksum_ok=}  expect {chkSum & 0xFF} got {c}"
                    )
                errored += 1
            self.reset_decoder()
            return

        # cant make any sense of this char
        # reset state and buffer
        if self.trace:
            logger.debug(f"stray character: '{c}' {c}")
        self.reset_decoder()

    def process(self):
        global beyond_range, frames, errored

        if self.frame_type == FrameType.REPLY:
            if self.frame[1] == 0x07:
                (_, _, _, v1, v2, v3, _) = struct.unpack("BBBBBBB", self.frame)
                logger.info(f" TF03 firmware version {v3}.{v2}.{v1}")
            else:
                logger.debug(
                    f"{self.frame_type}: len={len(self.frame)}"
                    f" {binascii.hexlify(self.frame)}"
                )
        if self.frame_type == FrameType.DISTANCE_REPORT:
            (_, _, distance, _, _, _) = struct.unpack("<BBHHHB", self.frame)
            # print(f"{self.frame_type}: {distance=}")
            if distance == MAX_DISTANCE:
                beyond_range += 1
                skData = {
                    "updates": [
                        {
                            "values": [
                                {"path": "tf03.outOfRange", "value": True},
                                {"path": "tf03.connected", "value": True},
                                {"path": "tf03.noReading", "value": beyond_range},
                                {"path": "tf03.errored", "value": errored},
                                {"path": "tf03.frames", "value": frames},
                            ]
                        }
                    ]
                }
            else:
                skData = {
                    "updates": [
                        {
                            "values": [
                                {"path": "tf03.outOfRange", "value": False},
                                {"path": "tf03.altitude", "value": distance},
                                {"path": "tf03.errored", "value": errored},
                                {"path": "tf03.frames", "value": frames},
                                {"path": "tf03.connected", "value": True},
                            ]
                        }
                    ]
                }
            sys.stdout.write(json.dumps(skData))
            sys.stdout.write("\n")
            sys.stdout.flush()

        if self.frame_type == FrameType.NONE:
            logger.debug(
                f"----> unknown frame seen: len={len(self.frame)} {self.frame}"
            )


async def reader():
    transport = None
    while True:
        while not (transport and transport.serial):
            try:
                transport, protocol = await serial_asyncio.create_serial_connection(
                    loop, InputChunkProtocol, port, baudrate=speed
                )

                # protocol.send_command("5A 04 10 6E", comment="restore factory settings")

                protocol.transport = transport
                protocol.send_command(
                    "5A 05 07 00 66", comment="disable output")

                await asyncio.sleep(1)
                protocol.send_command(
                    "5A 04 01 5F", comment="get version number")

                await asyncio.sleep(1)
                protocol.send_command(
                    f"5A 06 03 {framerate&0x00ff:02x} {framerate>>8&0x00ff:02x}",
                    addchksum=True,
                    comment="set frame rate",
                )

                await asyncio.sleep(1)
                protocol.send_command(
                    "5A 05 07 01 67", comment="enable output")

            except Exception as e:
                logger.error(f"{e}")
                skData = {
                    "updates": [
                         {
                             "values": [
                                 {"path": "tf03.connected", "value": False}
                             ]
                         }
                    ]
                }
                sys.stdout.write(json.dumps(skData))
                sys.stdout.write("\n")
                sys.stdout.flush()
                time.sleep(open_retry)

        await asyncio.sleep(chunk_delay)
        protocol.resume_reading()


if __name__ == "__main__":
    logger = logging.getLogger("tf03")
    logger.setLevel(logging.DEBUG)
    # logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(name)s: %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s"
    )
    handler = logging.handlers.SysLogHandler(address="/dev/log")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.info("startup")
    loop = asyncio.get_event_loop()
    loop.run_until_complete(reader())
    loop.close()
