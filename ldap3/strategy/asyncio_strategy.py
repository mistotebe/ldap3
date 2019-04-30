"""
"""

# Created on 2016.07.10
#
# Author: Giovanni Cannata
#
# Copyright 2016 - 2018 Giovanni Cannata
# Copyright 2019 Ondřej Kuzník
#
# This file is part of ldap3.
#
# ldap3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ldap3 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ldap3 in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.

import asyncio
import ssl
from weakref import ref

from ..core.connection import Connection
from ..core.exceptions import LDAPSocketOpenError
from ..protocol.rfc4511 import LDAPMessage
from ..strategy.base import BaseStrategy
from ..utils.asn1 import decoder, decode_message_fast
from ..utils.log import log, log_enabled, format_ldap_message, \
    BASIC, ERROR, EXTENDED

LDAP_MESSAGE_TEMPLATE = LDAPMessage()
INTERMEDIATE_RESULTS = [
    'searchResEntry',
    'searchResRef',
    'intermediateResponse',
]


class LDAPRequest(asyncio.Future):
    "Awaitable/iterable object that corresponds to the request"

    def __init__(self, connection, message_id):
        super().__init__()
        self.full_result = None
        self.connection = ref(connection)
        self.message_id = message_id
        self._queue = asyncio.Queue()

    def on_message(self, message):
        "Message callback to enqueue the result"
        if self.done():
            if log_enabled(ERROR):
                log(ERROR, 'message %d for <%s> should not have been received',
                    self.message_id, self.connection)
            return

        if message['type'] in INTERMEDIATE_RESULTS:
            self._queue.put_nowait(message)
        else:
            self.full_result = message
            self.set_result(message['result'])
            self.connection.requests.pop(self.message_id, None)

    async def __aiter__(self):
        next_item = asyncio.create_task(self._queue.get())
        while not self.done():
            done, _ = await asyncio.wait({self, next_item},
                                         return_when=asyncio.FIRST_COMPLETED)
            if next_item in done:
                yield next_item.result()
                next_item = asyncio.create_task(self._queue.get())

        if next_item.done():
            yield next_item.result()
        else:
            next_item.cancel()

        while not self._queue.empty():
            yield self._queue.get_nowait()

class LDAPProtocol(asyncio.BaseProtocol):
    "Decapsulates data from the stream"

    def __init__(self, connection):
        self.connection = ref(connection)
        self.transport = None

        self.buffer = bytearray()
        self._pdu_len = -1
        self.loop = None

    def connection_made(self, transport):
        "Transport connected"
        self.transport = transport
        self.loop = asyncio.get_running_loop()

    async def start_tls(self):
        "Initiate TLS set up, which switches our transport on success"
        ssl_context = ssl.create_default_context()
        self.transport = await self.loop.start_tls(self.transport, self, ssl_context)

    def data_received(self, data):
        "Process as many messages as we can decode"
        self.buffer.extend(data)

        pdu_len = self._pdu_len
        if pdu_len <= 0:
            pdu_len = BaseStrategy.compute_ldap_message_size(self.buffer)

        while pdu_len > 0 and self._pdu_len <= len(self.buffer):
            pdu, self.buffer = self.buffer[pdu_len:], self.buffer[:pdu_len]
            self.connection.strategy.process_pdu(pdu)

            pdu_len = BaseStrategy.compute_ldap_message_size(self.buffer)

        self._pdu_len = pdu_len

class AsyncConnection(Connection):
    def __init__(self, server, **kwargs):
        kwargs['strategy'] = AsyncIOStrategy
        Connection.__init__(self, server, **kwargs)

        self.transport = None
        self.protocol = None

    def protocol_factory(self):
        "Attaches protocol to the connection"
        self.protocol = LDAPProtocol(self)
        return self.protocol

    def on_message(self, message_id, dict_response):
        "Callback for messages not related to existing requests"
        if message_id == 0:
            # 0 is reserved for 'Unsolicited Notification' from server as per RFC4511 (paragraph 4.4)
            if dict_response['responseName'] == '1.3.6.1.4.1.1466.20036':
                # Notice of Disconnection as per RFC4511 (paragraph 4.4.1)
                self.last_error = 'connection closed by server'
            else:
                self.last_error = 'unknown unsolicited notification from server'
            if log_enabled(ERROR):
                log(ERROR, '<%s> for <%s>', self.connection.last_error, self.connection)
            self.close()
        else:
            if log_enabled(BASIC):
                log(BASIC, 'ignoring message %d for <%s>', message_id, self.connection)


# noinspection PyProtectedMember
class AsyncIOStrategy(BaseStrategy):
    """
    This strategy streams responses into per-request generators/futures
    (maintained internally in the self._responses container)

    It is asynchronous for operations sent, not for internal setup yet.
    """
    def __init__(self, ldap_connection, loop=None):
        BaseStrategy.__init__(self, ldap_connection)
        self._loop = loop or asyncio.get_event_loop()

    async def open(self):
        if not self.connection.protocol:
            exception_history = []
            for candidate_address in self.connection.server.candidate_addresses():
                try:
                    if log_enabled(BASIC):
                        log(BASIC, 'try to open candidate address %s', candidate_address[:-2])
                    if self.connection.server.ipc:
                        await self._loop.create_unix_connection(
                            self.connection.protocol_factory, candidate_address)
                    else:
                        await self._loop.create_connection(
                            self.connection.protocol_factory, candidate_address)
                    self.connection.server.current_address = candidate_address
                    self.connection.server.update_availability(candidate_address, True)
                    break
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    self.connection.server.update_availability(candidate_address, False)
                    exception_history.append((type(e)(str(e)), candidate_address[4]))
            if not self.connection.server.current_address and exception_history:
                if log_enabled(ERROR):
                    log(ERROR, 'unable to open socket for <%s>', self.connection)
                raise LDAPSocketOpenError('unable to open socket', exception_history)
            elif not self.connection.server.current_address:
                if log_enabled(ERROR):
                    log(ERROR, 'invalid server address for <%s>', self.connection)
                raise LDAPSocketOpenError('invalid server address')

    def process_pdu(self, pdu):
        "Decode PDU and issue callback"
        if self.connection.fast_decoder:
            ldap_resp = decode_message_fast(pdu)
            dict_response = self.decode_response_fast(ldap_resp)
        else:
            # unprocessed unused because receiving() waits for the whole message
            ldap_resp, _ = decoder.decode(pdu, asn1Spec=LDAP_MESSAGE_TEMPLATE)
            dict_response = self.decode_response(ldap_resp)
        if log_enabled(EXTENDED):
            log(EXTENDED, 'ldap message received via <%s>:%s', self.connection, format_ldap_message(ldap_resp, '<<'))

        message_id = int(ldap_resp['messageID'])
        request = self.connection.requests.get(message_id)
        if request:
            request.on_message(dict_response)
        else:
            self.connection.on_message(message_id, dict_response)

    def _start_listen(self):
        self._loop.add_reader(self.connection.socket, self._read)
        BaseStrategy._start_listen(self)

    def _stop_listen(self):
        BaseStrategy._stop_listen(self)
        self._loop.remove_reader(self.connection.socket)

    def _open_socket(self, address, use_ssl=False, unix_socket=False):
        BaseStrategy._open_socket(self, address, use_ssl, unix_socket)
        self.connection.socket.setblocking(False)

    def get_response(self, message_id, timeout=None, get_request=False):
        """
        Get response messages for a given message_id

        Not implemented since we provide a pollable/iterable Operation object.
        """
        raise NotImplementedError

    def _read(self):
        pass
