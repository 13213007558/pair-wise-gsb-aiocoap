# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""RFC9175 Echo option support

When a server is about to send a large response to a request it received over
the public Internet, it can not be sure that the source address of the request
was not spoofed (and would thus be amplifying traffic toward a victim). The
Echo option, specified in RFC9175, lets the server issue a challenge that the
client has to echo back before the actual resource handler is invoked.

This module provides the building blocks for that pattern:

* :class:`EchoPolicy` decides how Echo values are produced and when a
  presented value is considered valid (how long it is valid for, and which
  properties of the request it is bound to).
  :class:`AddressBoundEchoPolicy` is provided as an implementation that binds
  Echo values to the peer's address.

* :class:`EchoChallengeResource` wraps any regular resource and answers
  requests that do not carry a currently valid Echo value with 4.01
  Unauthorized and a fresh Echo option. The wrapped resource's handler (which
  may have side effects) is only invoked once the reachability challenge has
  been passed; any user authentication remains the business of the wrapped
  resource.

* :class:`EchoRetryingRequestProvider` wraps a client-side request provider
  (typically a :class:`aiocoap.Context`) and transparently re-sends a request
  with the Echo option when the server challenges it, preserving the original
  method, payload and options. The number of retries is bounded so that a
  server that keeps challenging can not cause an infinite loop.

The validity of Echo values is evaluated against a clock that can be injected
into the policy, which makes expiring values testable with a controlled
clock::

    >>> from types import SimpleNamespace
    >>> now = [1000.0]
    >>> policy = AddressBoundEchoPolicy(secret=b"demo secret", validity=30, clock=lambda: now[0])
    >>> peer = SimpleNamespace(hostinfo="192.0.2.1:5683")
    >>> echo = policy.issue(peer)
    >>> policy.validate(echo, peer)
    True
    >>> now[0] = 1029.0  # same Echo, still within its validity
    >>> policy.validate(echo, peer)
    True
    >>> now[0] = 1031.0  # same Echo, now expired
    >>> policy.validate(echo, peer)
    False
    >>> now[0] = 1001.0  # not expired, but replayed from another source
    >>> policy.validate(echo, SimpleNamespace(hostinfo="198.51.100.7:5683"))
    False
    >>> policy.validate(b"not-an-echo-value", peer)
    False
"""

import asyncio
import hashlib
import hmac
import secrets
import struct
import time

from . import interfaces
from . import message
from . import resource
from .numbers.codes import Code
from .util import hostportsplit

_FORMAT_VERSION = b"\x01"
_TIMESTAMP = struct.Struct("!I")
_TAG_LENGTH = 8
_ECHO_LENGTH = len(_FORMAT_VERSION) + _TIMESTAMP.size + _TAG_LENGTH


class EchoPolicy:
    """Decision point for issuing and validating Echo option values.

    Implementations decide how long an Echo value stays valid and which
    properties of the request (eg. the peer's address) a value is bound to.
    """

    def issue(self, remote: interfaces.EndpointAddress) -> bytes:
        """Produce a fresh Echo value to challenge the given remote with."""
        raise NotImplementedError()

    def validate(self, echo_value: bytes, remote: interfaces.EndpointAddress) -> bool:
        """Return True if the Echo value presented by the given remote is
        currently valid for it."""
        raise NotImplementedError()


class AddressBoundEchoPolicy(EchoPolicy):
    """Echo policy that binds values to the peer's address and an expiry time.

    Echo values are self-contained: they carry the time they were issued at,
    authenticated with an HMAC over the issuing time and the peer's address
    (not its port, so a client that comes back from a different port of the
    same address is still recognized). The server thus does not need to keep
    any per-client state.

    A presented value is only valid if it is well-formed, its authentication
    tag matches the presenting peer's address, and it has been issued no
    longer than ``validity`` seconds ago (as told by ``clock``, which defaults
    to :func:`time.monotonic` and can be replaced in tests).

    If no ``secret`` is given, a random one is generated; Echo values then
    stop being valid across server restarts, which is usually acceptable for
    reachability challenges.
    """

    def __init__(
        self, secret: bytes = None, validity: float = 60.0, clock=time.monotonic
    ):
        self._secret = secret if secret is not None else secrets.token_bytes(16)
        self.validity = validity
        self._clock = clock

    @staticmethod
    def _scope(remote: interfaces.EndpointAddress) -> bytes:
        host, _port = hostportsplit(remote.hostinfo)
        return host.encode("utf8")

    def _tag(self, timestamp: bytes, scope: bytes) -> bytes:
        return hmac.new(
            self._secret,
            _FORMAT_VERSION + timestamp + scope,
            hashlib.sha256,
        ).digest()[:_TAG_LENGTH]

    def issue(self, remote: interfaces.EndpointAddress) -> bytes:
        timestamp = _TIMESTAMP.pack(int(self._clock()))
        return _FORMAT_VERSION + timestamp + self._tag(timestamp, self._scope(remote))

    def validate(self, echo_value: bytes, remote: interfaces.EndpointAddress) -> bool:
        if len(echo_value) != _ECHO_LENGTH or not echo_value.startswith(
            _FORMAT_VERSION
        ):
            return False
        timestamp = echo_value[
            len(_FORMAT_VERSION) : len(_FORMAT_VERSION) + _TIMESTAMP.size
        ]
        (issued,) = _TIMESTAMP.unpack(timestamp)
        expected_tag = self._tag(timestamp, self._scope(remote))
        if not hmac.compare_digest(echo_value[-_TAG_LENGTH:], expected_tag):
            return False
        now = self._clock()
        return issued <= now <= issued + self.validity


class EchoChallengeResource(resource.Resource):
    """Resource wrapper that requires a valid Echo option before rendering.

    Requests that carry no Echo value, an expired one, one that was issued for
    a different peer, or a malformed one, are answered with 4.01 Unauthorized
    carrying a freshly issued Echo value, as described in RFC9175. The wrapped
    resource's handler is only invoked once a valid Echo value is presented,
    so handlers with side effects are never triggered by unverified peers.

    This only verifies that the peer can receive messages at the address it
    claims to have; authenticating the user remains the responsibility of the
    wrapped resource.
    """

    def __init__(self, inner: interfaces.Resource, policy: EchoPolicy):
        super().__init__()
        self.inner = inner
        self.policy = policy

    async def needs_blockwise_assembly(self, request):
        return await self.inner.needs_blockwise_assembly(request)

    async def render(self, request):
        echo = request.opt.echo
        if echo is None or not self.policy.validate(echo, request.remote):
            response = message.Message(
                code=Code.UNAUTHORIZED,
                payload=b"Echo option required (see RFC9175)",
            )
            response.opt.echo = self.policy.issue(request.remote)
            return response
        return await self.inner.render(request)

    def get_link_description(self):
        if hasattr(self.inner, "get_link_description"):
            return self.inner.get_link_description()
        return super().get_link_description()


class _EchoRetryingRequest(interfaces.Request):
    def __init__(self):
        self.response = asyncio.get_running_loop().create_future()


class EchoRetryingRequestProvider(interfaces.RequestProvider):
    """Client-side wrapper that answers Echo challenges (RFC9175).

    When a request sent through this provider is answered with 4.01
    Unauthorized carrying an Echo option, the request is re-sent with that
    Echo option set. The re-sent request preserves the original method,
    payload and options (only message ID and token are renewed).

    At most ``max_retries`` re-sends happen per request; if the server keeps
    challenging (or keeps rejecting the presented Echo values), the final
    4.01 response is passed on to the caller rather than looping forever.
    """

    def __init__(self, inner: interfaces.RequestProvider, max_retries: int = 2):
        self.inner = inner
        self.max_retries = max_retries

    def request(self, request_message, handle_blockwise=True):
        result = _EchoRetryingRequest()

        async def run():
            echo = None
            retries_left = self.max_retries
            try:
                while True:
                    attempt = request_message.copy(mid=None, token=None)
                    if echo is not None:
                        attempt.opt.echo = echo
                    response = await self.inner.request(
                        attempt, handle_blockwise=handle_blockwise
                    ).response
                    if (
                        response.code == Code.UNAUTHORIZED
                        and response.opt.echo is not None
                        and retries_left > 0
                    ):
                        retries_left -= 1
                        echo = response.opt.echo
                        continue
                    result.response.set_result(response)
                    return
            except Exception as err:
                if not result.response.done():
                    result.response.set_exception(err)

        asyncio.get_running_loop().create_task(run())
        return result
