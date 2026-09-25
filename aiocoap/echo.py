# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Server- and client-side support for the Echo option of RFC9175_.

The Echo option allows a server to verify that a client is reachable at the
address it sends from before investing into large responses or executing
requests with side effects, and gives the server a freshness proof for the
request.

On the server side, an :class:`EchoPolicy` decides what Echo values are
issued, what they are bound to and how long they stay valid; the
:class:`EchoResourceWrapper` applies such a policy to any
:class:`aiocoap.interfaces.Resource`. Requests that do not carry a currently
valid Echo option are challenged with a 4.01 response carrying a fresh Echo
value; the wrapped resource's handler (which may have side effects) is only
invoked once the challenge has been answered successfully.

On the client side, requests managed by a :class:`aiocoap.protocol.Context`
(ie. ``Context.request()`` calls with their default blockwise handling)
automatically answer a bounded number of Echo challenges by re-sending the
request -- method, payload and all other options unchanged -- with the Echo
option the server provided.

Note that this mechanism only verifies *reachability* of the peer at its
address; authenticating the peer's identity remains up to the application
(eg. through OSCORE, (D)TLS or application level credentials).

.. _RFC9175: https://www.rfc-editor.org/rfc/rfc9175
"""

import hashlib
import hmac
import secrets
import struct
import time

from . import interfaces
from .message import Message
from .numbers import UNAUTHORIZED

__all__ = [
    "EchoPolicy",
    "AddressBoundEchoPolicy",
    "EchoResourceWrapper",
]


class EchoPolicy:
    """Server-side policy that decides which Echo values are acceptable for a
    request.

    The policy owns the Echo value format: :meth:`issue` creates a value when
    a request is being challenged, and :meth:`validate` decides whether the
    Echo option of an incoming request is currently acceptable. Implementations
    define the lifetime of issued values and what they are bound to (eg. the
    peer's address); values that are expired, were issued for a different
    peer, or are not well-formed must be rejected so the requester gets
    challenged again.
    """

    def issue(self, request) -> bytes:
        """Create an Echo value to challenge the sender of the given request."""
        raise NotImplementedError()

    def validate(self, request) -> bool:
        """Return True if the request's Echo option is currently acceptable,
        False if the requester should be challenged (again)."""
        raise NotImplementedError()


class AddressBoundEchoPolicy(EchoPolicy):
    """Stateless Echo policy that binds Echo values to the transport address
    of the requesting peer and limits their lifetime.

    Echo values are self-contained (an expiry timestamp, integrity protected
    together with the peer's address using an HMAC), so no per-peer state is
    kept; the ``secret`` needs to be shared between all server processes that
    should accept each other's Echo values. If no secret is given, a random
    one is generated (which invalidates all previously issued values when the
    server restarts -- usually acceptable for a reachability check).

    ``lifetime`` is the number of seconds for which an issued Echo value
    stays valid. It is measured using ``clock``, which defaults to
    :func:`time.monotonic` and can be replaced (eg. with a controllable clock
    in tests).

    Values that are expired, were issued for a different peer address, or are
    not well-formed at all are rejected; the requester will be challenged
    again.
    """

    _VERSION = 1
    _COUNTER_FORMAT = "!BQ"
    _COUNTER_SIZE = struct.Struct(_COUNTER_FORMAT).size

    def __init__(self, *, secret=None, lifetime=30.0, clock=time.monotonic, tag_size=8):
        self._secret = secret if secret is not None else secrets.token_bytes(32)
        self.lifetime = float(lifetime)
        self._clock = clock
        self._tag_size = tag_size

    @staticmethod
    def _binding(request):
        """The data an Echo value is bound to for the given request, or None
        if the request can not be bound (and thus never validated)."""
        remote = request.remote
        if remote is None:
            return None
        return remote.hostinfo.encode("utf8")

    def _tag(self, counter, binding):
        return hmac.new(
            self._secret,
            struct.pack(self._COUNTER_FORMAT, self._VERSION, counter) + binding,
            hashlib.sha256,
        ).digest()[: self._tag_size]

    def issue(self, request) -> bytes:
        binding = self._binding(request)
        if binding is None:
            raise ValueError(
                "Can not issue an Echo value for a request without a remote"
            )
        counter = int((self._clock() + self.lifetime) * 1_000_000)
        return struct.pack(self._COUNTER_FORMAT, self._VERSION, counter) + self._tag(
            counter, binding
        )

    def validate(self, request) -> bool:
        value = request.opt.echo
        if value is None:
            return False
        binding = self._binding(request)
        if binding is None:
            return False
        if len(value) != self._COUNTER_SIZE + self._tag_size:
            return False
        version, counter = struct.unpack(
            self._COUNTER_FORMAT, value[: self._COUNTER_SIZE]
        )
        if version != self._VERSION:
            return False
        if counter <= int(self._clock() * 1_000_000):
            # expired
            return False
        expected = self._tag(counter, binding)
        return hmac.compare_digest(value[self._COUNTER_SIZE :], expected)


class EchoResourceWrapper(interfaces.Resource):
    """Wraps a resource and requires requests to carry a valid Echo option
    (as per the given policy) before the wrapped resource's handler is
    invoked.

    Requests without a valid Echo option are answered with a 4.01 response
    carrying a fresh Echo value (a challenge as described in RFC9175);
    clients that answer the challenge are then served by the wrapped
    resource. The wrapped resource's handler is never invoked for requests
    that did not answer the challenge, so any side effects of the handler
    only happen after the requester's reachability was verified.
    """

    def __init__(self, inner: interfaces.Resource, policy: EchoPolicy):
        super().__init__()
        self._inner = inner
        self._policy = policy

    async def needs_blockwise_assembly(self, request):
        return await self._inner.needs_blockwise_assembly(request)

    async def render(self, request):
        if not self._policy.validate(request):
            challenge = Message(code=UNAUTHORIZED, payload=b"Echo option required")
            challenge.opt.echo = self._policy.issue(request)
            return challenge
        return await self._inner.render(request)
