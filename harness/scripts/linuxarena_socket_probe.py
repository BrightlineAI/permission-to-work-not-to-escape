"""Fixed model-free socket probes inside the native fixture's confinement only.

No audit configuration is changed: AUDIT_SET uses a zero update mask. Unexpected
success, absent kernel support and malformed responses fail required assertions.
This module is staged read-only alongside the trusted launcher, not an agent API.
"""
import ctypes
import errno
import hashlib
import json
import os
import runpy
import socket
import struct
import sys


def rejected(action, expected=(errno.EPERM,)):
    try:
        action()
    except OSError as exc:
        assert exc.errno in expected, exc
        return exc.errno
    raise AssertionError('Forbidden socket operation succeeded')


def audit_request(sock, message_type, payload=b''):
    """Retain only error codes; never save host audit contents."""
    sequence = message_type
    packet = struct.pack('<IHHII', 16 + len(payload), message_type, 5, sequence, 0) + payload
    sock.sendto(packet, (0, 0))  # NLM_F_REQUEST | NLM_F_ACK, kernel destination
    reply, sender = sock.recvfrom(4096)
    assert sender == (0, 0) and len(reply) >= 36, 'Missing kernel audit acknowledgement'
    size, kind, flags, observed_seq, port = struct.unpack_from('<IHHII', reply)
    assert 36 <= size <= len(reply) and kind == 2 and observed_seq == sequence, \
        'Unexpected audit acknowledgement'
    result = -struct.unpack_from('<i', reply, 16)[0]
    # Rootless native user namespaces are rejected by the kernel with
    # ECONNREFUSED. No launcher/PAM errno translation is performed.
    assert result in (errno.EPERM, errno.ECONNREFUSED), ('Audit request accepted', result)
    return result


def observe():
    status = dict(line.split(':', 1) for line in open('/proc/self/status'))
    allowed = sum(1 << bit for bit in (7, 6, 1, 0, 3, 5))
    caps = {key: int(status[key].strip(), 16)
            for key in ('CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb')}
    print(json.dumps({'socket_probe_uid': os.getuid(), 'capabilities': caps}),
          file=sys.stderr, flush=True)
    assert all(value & ~allowed == 0 for value in caps.values()), \
        ('Capability outside native ceiling retained', caps)
    assert int(status['NoNewPrivs']) == 1 and int(status['Seccomp']) == 2
    for name in os.listdir('/proc/self/fd'):
        try:
            target = os.readlink('/proc/self/fd/' + name)
        except FileNotFoundError:
            continue
        assert 'ptw-native-socket-filter' not in target, 'Filter descriptor leaked to payload'
    result = {'uid': os.getuid(), 'capabilities': caps, 'no_new_privs': 1, 'seccomp': 2}
    launcher = runpy.run_path('/ptw-native-tools/launcher.py')
    result['filter_sha256'] = hashlib.sha256(launcher['socket_filter']()).hexdigest()
    # Audit socket creation must actually work; an unavailable subsystem is not
    # evidence for this compatibility exception.
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 9) as audit:
        audit.settimeout(2)
        audit.bind((0, 0))
        result['audit_open'] = True
        result['audit_get_denied'] = audit_request(audit, 1000)
        result['audit_set_denied'] = audit_request(audit, 1001, bytes(44))
        result['audit_user_denied'] = audit_request(audit, 1005, b'ptw synthetic probe\0')
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 9) as peer:
            peer.bind((0, 0))
            result['audit_peer_denied'] = rejected(lambda: audit.sendto(b'probe', peer.getsockname()))
            peer.setblocking(False)
            result['audit_peer_empty'] = rejected(lambda: peer.recv(100), (errno.EAGAIN,))
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 9) as audit:
        result['audit_multicast_denied'] = rejected(lambda: audit.bind((0, 1)))
    for name, family, kind, protocol in (
            ('udp4', 2, 2, 17), ('udp6', 10, 2, 17), ('raw4', 2, 3, 1),
            ('raw6', 10, 3, 58), ('sctp', 2, 1, 132), ('packet', 17, 3, 0),
            ('route_netlink', 16, 3, 0), ('generic_netlink', 16, 3, 16),
            ('audit_datagram', 16, 2, 9)):
        result[name] = rejected(lambda: socket.socket(family, kind, protocol))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    for name, number in (('io_uring_setup', 425), ('x32_socket', 0x40000029)):
        ctypes.set_errno(0)
        code = libc.syscall(ctypes.c_long(number), ctypes.c_long(0), ctypes.c_long(0), ctypes.c_long(0))
        error = ctypes.get_errno()
        assert code == -1 and error == errno.EPERM, (name, code, error)
        result[name] = error
    pair = (ctypes.c_int * 2)()
    for family in (2, 10, 16):
        ctypes.set_errno(0)
        code = libc.syscall(ctypes.c_long(53), ctypes.c_long(family), ctypes.c_long(1),
                            ctypes.c_long(0), pair)
        error = ctypes.get_errno()
        assert code == -1 and error == errno.EPERM, ('socketpair', family, code, error)
        result['socketpair_' + str(family)] = error
    left, right = socket.socketpair()
    with left, right:
        left.sendall(b'useful IPC')
        assert right.recv(100) == b'useful IPC'
    result['unix_socketpair'] = True
    try:
        with socket.create_connection(('127.0.0.1', 32002), timeout=2):
            raise AssertionError('Forbidden TCP port reachable')
    except OSError as exc:
        assert exc.errno in (errno.EACCES, errno.EPERM), exc
        result['tcp_port_denied'] = exc.errno
    return result


if __name__ == '__main__':
    print(json.dumps(observe(), sort_keys=True))
