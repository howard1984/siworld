"""Inspect AMD64 PE imports without loading the executable or third-party code."""
import re
import struct


SYSTEM_DLLS = frozenset({
    # getrandom uses ProcessPrng from this inbox Windows 10/11 system library.
    'advapi32.dll', 'bcrypt.dll', 'bcryptprimitives.dll', 'crypt32.dll', 'dbghelp.dll',
    'iphlpapi.dll', 'kernel32.dll', 'ncrypt.dll', 'normaliz.dll',
    'ntdll.dll', 'ole32.dll', 'oleaut32.dll', 'powrprof.dll',
    'psapi.dll', 'rpcrt4.dll', 'secur32.dll', 'shell32.dll',
    'user32.dll', 'userenv.dll', 'version.dll', 'ws2_32.dll',
})


def imports(data):
    """Return ordinary and delay imports; malformed or non-AMD64 PE files fail."""
    def unpack(fmt, offset):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(data):
            raise ValueError('Truncated PE structure')
        return struct.unpack_from(fmt, data, offset)

    if data[:2] != b'MZ':
        raise ValueError('Missing DOS header')
    pe, = unpack('<I', 0x3c)
    if data[pe:pe + 4] != b'PE\0\0':
        raise ValueError('Missing PE signature')
    machine, count, _, _, _, optional_size, _ = unpack('<HHIIIHH', pe + 4)
    optional = pe + 24
    magic, = unpack('<H', optional)
    if machine != 0x8664 or magic != 0x20b or optional_size < 112:
        raise ValueError('Expected an AMD64 PE32+ executable')
    image_base, = unpack('<Q', optional + 24)
    header_size, = unpack('<I', optional + 60)
    directory_count, = unpack('<I', optional + 108)
    if directory_count > (optional_size - 112) // 8:
        raise ValueError('Truncated PE data directories')
    sections = []
    for index in range(count):
        section = optional + optional_size + index * 40
        _, virtual_address, raw_size, raw_offset = unpack('<IIII', section + 8)
        if raw_offset + raw_size > len(data):
            raise ValueError('Truncated PE section')
        sections.append((virtual_address, raw_size, raw_offset))

    def offset(rva, size):
        if rva < header_size and rva + size <= min(header_size, len(data)):
            return rva
        for address, raw_size, raw_offset in sections:
            if address <= rva and rva + size <= address + raw_size:
                return raw_offset + rva - address
        raise ValueError('PE RVA is not backed by file data')

    def dll_name(rva):
        name = bytearray()
        for index in range(260):
            value = data[offset(rva + index, 1)]
            if not value:
                break
            name.append(value)
        else:
            raise ValueError('Unterminated PE DLL name')
        try:
            name = name.decode('ascii').lower()
        except UnicodeDecodeError as error:
            raise ValueError('Non-ASCII PE DLL name') from error
        if not re.fullmatch(r'[a-z0-9_.-]+\.dll', name):
            raise ValueError('Invalid PE DLL name')
        return name

    result = {}
    for kind, directory, descriptor_size in [('imports', 1, 20), ('delay_imports', 13, 32)]:
        names = set()
        if directory < directory_count:
            rva, size = unpack('<II', optional + 112 + directory * 8)
            if bool(rva) != bool(size):
                raise ValueError('Incomplete PE import directory')
            if rva:
                terminated = False
                for position in range(0, size - descriptor_size + 1, descriptor_size):
                    fields = unpack('<' + 'I' * (descriptor_size // 4), offset(rva + position, descriptor_size))
                    if not any(fields):
                        terminated = True
                        break
                    name_rva = fields[3] if directory == 1 else fields[1]
                    if directory == 13:
                        if fields[0] not in (0, 1):
                            raise ValueError('Unsupported PE delay-import attributes')
                        if fields[0] == 0:
                            name_rva -= image_base
                    names.add(dll_name(name_rva))
                if not terminated:
                    raise ValueError('Unterminated PE import directory')
        result[kind] = sorted(names)
    if not result['imports']:
        raise ValueError('Expected Windows system imports')
    return result


def audit(path):
    """Accept only reviewed Windows system DLLs, excluding dynamic CRTs."""
    result = imports(path.read_bytes())
    for name in result['imports'] + result['delay_imports']:
        if name not in SYSTEM_DLLS and not re.fullmatch(r'api-ms-win-core-[a-z0-9-]+\.dll', name):
            raise ValueError(f'Unreviewed or dynamic runtime DLL dependency: {name}')
    return {'machine': 'AMD64', **result, 'dynamic_crt': False}
