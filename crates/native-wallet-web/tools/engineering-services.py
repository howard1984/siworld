"""Bounded loopback engineering adapters. No wallet scan, keys or remote proving."""
import argparse
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import socket
import struct
import os
import stat
import sqlite3
import subprocess
import threading
import time
from urllib.parse import urlsplit, parse_qs

SNAPSHOT = 524288
ZERO = '00' * 32

def canonical_hex(value, size=32):
    if not isinstance(value, str) or len(value) != size * 2 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Invalid canonical identifier.')
    return value

def auth_message(origin, method, locator, challenge, revision, body, previous):
    return f'SWVAUTH1\n{origin}\n{method}\n{locator}\n{challenge}\n{revision}\n{hashlib.sha256(body).hexdigest()}\n{previous}\n'.encode()

def revision_message(locator, revision, digest, previous):
    return f'SWVREV1\n{locator}\n{revision}\n{digest}\n{previous}\n'.encode()

def chain_page(index, tip, start, limit):
    canonical_hex(tip)
    ids = index['ids']
    end = 0 if tip == index['genesis'] else ids.index(tip) + 1
    if start < 1 or start > end + 1 or not 1 <= limit <= 128:
        raise ValueError('Invalid pinned index range.')
    return {'ids': ids[start-1:min(end, start-1+limit)]}

def explorer_projection(value, index):
    """Reject extensions outside the public aggregate projection contract."""
    def exact(item, fields):
        if type(item) is not dict or set(item) != set(fields.split()):
            raise ValueError('Public explorer projection unavailable.')
    def integer(item, maximum=1000000):
        if type(item) is not int or not 0 <= item <= maximum:
            raise ValueError('Invalid public explorer integer.')
    def atoms(item):
        if item is None:
            return
        if type(item) is not str or not 1 <= len(item) <= 39 or any(c not in '0123456789' for c in item) or (len(item) > 1 and item[0] == '0') or int(item) >= 1 << 128:
            raise ValueError('Invalid public explorer amount.')
    exact(value, 'version network genesis height tip published_unix_seconds blocks economics checkpoint governance')
    if value['version'] != 1 or any(value[key] != index[key] for key in ('network', 'genesis', 'height', 'tip')):
        raise ValueError('Public explorer snapshot identity differs.')
    for key in ('network', 'genesis', 'tip'): canonical_hex(value[key])
    integer(value['height']); integer(value['published_unix_seconds'], (1 << 53) - 1)
    if value['height'] == 0 and value['tip'] != value['genesis']:
        raise ValueError('Public explorer genesis differs.')
    if type(value['blocks']) is not list or len(value['blocks']) > 101:
        raise ValueError('Public explorer block limit.')
    previous = None
    for block in value['blocks']:
        exact(block, 'height hash parent_hash timestamp target slots_including_padding reward_mode work')
        integer(block['height']); integer(block['timestamp'], (1 << 53) - 1)
        for key in ('hash', 'parent_hash', 'target'): canonical_hex(block[key])
        target = int(block['target'], 16)
        if target == 0 or type(block['work']) is not str or block['work'] != str((1 << 256) // (target + 1)) or not 0 < block['height'] <= value['height']:
            raise ValueError('Invalid public explorer header work.')
        slots = block['slots_including_padding']
        if type(slots) is not int or not 64 <= slots <= 576 or slots % 16 or block['reward_mode'] not in ('holder', 'voyager'):
            raise ValueError('Invalid public explorer block metadata.')
        if previous is not None and (previous['height'] + 1 != block['height'] or previous['hash'] != block['parent_hash']):
            raise ValueError('Public explorer sample is not contiguous.')
        previous = block
    if previous is not None and (previous['height'] != value['height'] or previous['hash'] != value['tip']):
        raise ValueError('Public explorer sample tip differs.')
    economics = value['economics']
    exact(economics, 'issued_atoms burned_atoms holder_pool_atoms locked_reward_atoms unlock_schedule unlock_schedule_complete funds circulating_estimate_atoms')
    for key in ('issued_atoms', 'burned_atoms', 'holder_pool_atoms', 'locked_reward_atoms', 'circulating_estimate_atoms'): atoms(economics[key])
    if type(economics['unlock_schedule_complete']) is not bool:
        raise ValueError('Invalid public explorer schedule coverage.')
    for name, limit, fields in [('unlock_schedule', 64, 'height atoms'), ('funds', 32, 'index entitled_atoms released_atoms spent_atoms')]:
        if type(economics[name]) is not list or len(economics[name]) > limit:
            raise ValueError('Public explorer aggregate limit.')
        for row in economics[name]: exact(row, fields)
    last = value['height']
    for row in economics['unlock_schedule']:
        integer(row['height'], (1 << 53) - 1); atoms(row['atoms'])
        if row['height'] <= last:
            raise ValueError('Invalid public explorer unlock schedule.')
        last = row['height']
    for position, fund in enumerate(economics['funds']):
        if type(fund['index']) is not int or fund['index'] != position:
            raise ValueError('Invalid public explorer fund index.')
        for key in ('entitled_atoms', 'released_atoms', 'spent_atoms'): atoms(fund[key])
        if all(fund[key] is not None for key in ('entitled_atoms', 'released_atoms', 'spent_atoms')) and not int(fund['spent_atoms']) <= int(fund['released_atoms']) <= int(fund['entitled_atoms']):
            raise ValueError('Invalid public explorer fund totals.')
    if value['checkpoint'] is not None:
        checkpoint = value['checkpoint']
        exact(checkpoint, 'height hash issued_unix_seconds roster signer_indices')
        integer(checkpoint['height']); integer(checkpoint['issued_unix_seconds'], (1 << 53) - 1)
        canonical_hex(checkpoint['hash']); canonical_hex(checkpoint['roster'])
        votes = checkpoint['signer_indices']
        if not 0 < checkpoint['height'] <= value['height'] or type(votes) is not list or not 2 <= len(votes) <= 3 or any(type(slot) is not int or not 0 <= slot < 3 for slot in votes) or len(set(votes)) != len(votes):
            raise ValueError('Invalid public explorer checkpoint slots.')
    governance = value['governance']
    exact(governance, 'current_signers fee_address fund_addresses changes')
    # Governance projection is versioned separately when the eng2 adapter exists.
    if any(item is not None for item in governance.values()):
        raise ValueError('Public governance projection version unavailable.')
    return value

def read_explorer(root):
    path = root / 'explorer.json'
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 131072 or info.st_nlink != 1:
            raise ValueError('Public explorer projection unavailable.')
        body = stream.read(131073)
        if len(body) > 131072:
            raise ValueError('Public explorer projection limit.')
    index = json.loads((root / 'chain.json').read_text())
    return explorer_projection(json.loads(body), index)

class VaultStore:
    def __init__(self, path, origin, accounts=10, clock=time.monotonic):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('CREATE TABLE IF NOT EXISTS accounts(locator TEXT PRIMARY KEY, key BLOB NOT NULL, revision INTEGER NOT NULL, digest TEXT NOT NULL); CREATE TABLE IF NOT EXISTS snapshots(locator TEXT, revision INTEGER, previous TEXT, digest TEXT, signature TEXT, body BLOB, PRIMARY KEY(locator,revision));')
        self.origin, self.maximum, self.clock = origin, accounts, clock
        self.challenges = {}
        self.lock = threading.RLock()

    def challenge(self, locator, method):
        canonical_hex(locator)
        if method not in ['GET', 'PUT', 'POST']:
            raise ValueError('Invalid challenge method.')
        with self.lock:
            self.challenges = {k: v for k, v in self.challenges.items() if v[2] > self.clock()}
            if len(self.challenges) >= 128:
                raise ValueError('Challenge capacity reached.')
            token = secrets.token_hex(32)
            self.challenges[token] = (locator, method, self.clock() + 60)
            return {'challenge': token, 'expires_in_seconds': 60}

    def authenticate(self, method, locator, body, headers, key=None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        canonical_hex(locator)
        challenge = canonical_hex(headers.get('X-Vault-Challenge'))
        signature = bytes.fromhex(canonical_hex(headers.get('X-Vault-Signature'), 64))
        previous = canonical_hex(headers.get('X-Vault-Previous'))
        revision_text = headers.get('X-Vault-Revision', '')
        if not revision_text.isdigit() or len(revision_text) > 18:
            raise ValueError('Invalid revision.')
        revision = int(revision_text)
        with self.lock:
            pending = self.challenges.pop(challenge, None)
            if not pending or pending[:2] != (locator, method) or pending[2] <= self.clock():
                raise ValueError('Expired, replayed or mismatched authentication challenge.')
            if key is None:
                row = self.db.execute('SELECT key FROM accounts WHERE locator=?', (locator,)).fetchone()
                if row is None:
                    raise ValueError('Vault authentication failed.')
                key = row[0]
            Ed25519PublicKey.from_public_bytes(key).verify(signature, auth_message(self.origin, method, locator, challenge, revision, body, previous))
        return revision, previous

    def create(self, locator, key, headers):
        if len(key) != 32:
            raise ValueError('Invalid authentication public key.')
        revision, previous = self.authenticate('POST', locator, key, headers, key)
        if revision != 0 or previous != ZERO:
            raise ValueError('Invalid initial revision.')
        with self.lock:
            if self.db.execute('SELECT count(*) FROM accounts').fetchone()[0] >= self.maximum:
                raise ValueError('Engineering enrollment quota reached.')
            self.db.execute('INSERT INTO accounts VALUES(?,?,0,?)', (locator, key, ZERO))
        return {'status': 'created', 'revision': '0'}

    def put(self, locator, body, headers):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if len(body) != SNAPSHOT or body[:8] != b'SWVSNP01':
            raise ValueError('Snapshot must be exactly 512 KiB.')
        revision, previous = self.authenticate('PUT', locator, body, headers)
        digest = hashlib.sha256(body).hexdigest()
        signature = canonical_hex(headers.get('X-Vault-Record'), 64)
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                row = self.db.execute('SELECT key,revision,digest FROM accounts WHERE locator=?', (locator,)).fetchone()
                if row is None or row[1:] != (revision, previous):
                    raise ValueError('Revision conflict; existing ciphertext was preserved.')
                Ed25519PublicKey.from_public_bytes(row[0]).verify(bytes.fromhex(signature), revision_message(locator, revision + 1, digest, previous))
                self.db.execute('INSERT INTO snapshots VALUES(?,?,?,?,?,?)', (locator, revision+1, previous, digest, signature, body))
                self.db.execute('UPDATE accounts SET revision=?,digest=? WHERE locator=?', (revision+1, digest, locator))
                self.db.execute('DELETE FROM snapshots WHERE locator=? AND revision < ?', (locator, revision-1))
                self.db.execute('COMMIT')
            except Exception:
                self.db.execute('ROLLBACK')
                raise
        return {'status': 'stored', 'revision': str(revision+1), 'digest': digest}

    def get(self, locator, headers):
        self.authenticate('GET', locator, b'', headers)
        with self.lock:
            row = self.db.execute('SELECT revision,previous,digest,signature,body FROM snapshots WHERE locator=? ORDER BY revision DESC LIMIT 1', (locator,)).fetchone()
            if row is None:
                raise ValueError('No encrypted snapshot has been committed.')
            return row

class Handler(BaseHTTPRequestHandler):
    server_version = 'EngineeringAdapter/1'
    def log_message(self, *_):
        pass  # No request bodies, authentication material or connection addresses.

    def reply(self, status, body=b'', kind='application/json', headers=None):
        self.send_response(status)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        if self.headers.get('Origin') == self.server.origin:
            self.send_header('Access-Control-Allow-Origin', self.server.origin)
            self.send_header('Vary', 'Origin')
            self.send_header('Access-Control-Expose-Headers', 'X-Vault-Revision, X-Vault-Previous, X-Vault-Digest, X-Vault-Record')
        for key, value in (headers or {}).items():
            self.send_header(key, str(value))
        self.end_headers()
        self.wfile.write(body)

    def body(self, maximum):
        if self.headers.get('Transfer-Encoding') or not self.headers.get('Content-Length', '').isdigit():
            raise ValueError('A bounded Content-Length is required.')
        length = int(self.headers['Content-Length'])
        if length > maximum:
            raise ValueError('Request byte limit exceeded.')
        data = self.rfile.read(length)
        if len(data) != length:
            raise ValueError('Truncated request.')
        return data

    def do_OPTIONS(self):
        if self.headers.get('Origin') != self.server.origin:
            self.reply(403)
            return
        self.reply(204, headers={'Access-Control-Allow-Methods':'GET, POST, PUT', 'Access-Control-Allow-Headers':'Content-Type, X-Vault-Challenge, X-Vault-Signature, X-Vault-Previous, X-Vault-Revision, X-Vault-Record', 'Access-Control-Max-Age':'300'})

    def native_request(self, method, path):
        parts=path.path.strip('/').split('/')
        if method=='GET' and path.path=='/v1/head':kind,body=0,b''
        elif method=='GET' and path.path=='/v1/chain':
            query=parse_qs(path.query)
            if set(query)!={'tip','from','limit'}:raise ValueError('Invalid index request.')
            body=json.dumps({'tip':canonical_hex(query['tip'][0]),'from':int(query['from'][0]),'limit':int(query['limit'][0])}).encode();kind=1
        elif method=='GET' and len(parts)==3 and parts[:2]==['v1','compact']:kind,body=2,bytes.fromhex(canonical_hex(parts[2]))
        elif method=='POST' and path.path=='/v1/transactions':kind,body=3,self.body(657622)
        else:raise ValueError('Unknown native resource.')
        mode=os.lstat(self.server.native_socket)
        if not stat.S_ISSOCK(mode.st_mode) or stat.S_IMODE(mode.st_mode)!=0o600 or mode.st_uid!=os.geteuid():raise ValueError('Private native socket ownership or mode differs.')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:
            stream.settimeout(35);stream.connect(self.server.native_socket);stream.sendall(bytes([kind])+struct.pack('<I',len(body))+body)
            def exact(n):
                parts=[];remaining=n
                while remaining:
                    part=stream.recv(remaining)
                    if not part:raise ValueError('Private response truncated.')
                    parts.append(part);remaining-=len(part)
                return b''.join(parts)
            header=exact(5);size=struct.unpack('<I',header[1:])[0]
            if size>8388656:raise ValueError('Native response limit.')
            data=exact(size)
            if header[0]!=0:raise ValueError('Native request unavailable.')
        self.reply(200,data,'application/octet-stream' if kind==2 else 'application/json')

    def handle_request(self, method):
        self.connection.settimeout(30)
        if self.headers.get('Origin') != self.server.origin:
            self.reply(403, b'{"error":"Origin rejected."}')
            return
        try:
            path = urlsplit(self.path)
            parts = path.path.strip('/').split('/')
            if self.server.role == 'chain' and method == 'GET' and path.path == '/v1/explorer' and not path.query:
                self.reply(200, json.dumps(read_explorer(self.server.data), separators=(',', ':')).encode())
                return
            if self.server.role=='chain' and getattr(self.server,'native_socket',None):
                self.native_request(method,path)
                return
            if self.server.role == 'vault':
                if method == 'POST' and path.path == '/v1/vault/challenge':
                    request = json.loads(self.body(1000))
                    if set(request) != {'locator','method'}:
                        raise ValueError('Invalid challenge request.')
                    result = self.server.store.challenge(request['locator'], request['method'])
                elif len(parts) == 4 and parts[:3] == ['v1','vault','accounts'] and method == 'POST':
                    result = self.server.store.create(parts[3], self.body(32), self.headers)
                elif len(parts) == 4 and parts[:3] == ['v1','vault','snapshot']:
                    if method == 'PUT':
                        result = self.server.store.put(parts[3], self.body(SNAPSHOT), self.headers)
                    elif method == 'GET':
                        revision, previous, digest, signature, body = self.server.store.get(parts[3], self.headers)
                        self.reply(200, body, 'application/octet-stream', {'X-Vault-Revision':revision,'X-Vault-Previous':previous,'X-Vault-Digest':digest,'X-Vault-Record':signature})
                        return
                    else:
                        raise ValueError('Unsupported operation.')
                else:
                    raise ValueError('Unknown Vault resource.')
            else:
                root = self.server.data
                index = json.loads((root/'chain.json').read_text())
                ids = index['ids']
                if method == 'GET' and path.path == '/v1/head':
                    result = {'network':index['network'],'genesis':index['genesis'],'height':len(ids),'tip':ids[-1] if ids else index['genesis']}
                elif method == 'GET' and path.path == '/v1/chain':
                    query = parse_qs(path.query)
                    if set(query) != {'tip','from','limit'} or any(len(v)!=1 for v in query.values()):
                        raise ValueError('Requested immutable chain is unavailable.')
                    result=chain_page(index,query['tip'][0],int(query['from'][0]),int(query['limit'][0]))
                elif method == 'GET' and len(parts) == 3 and parts[:2] == ['v1','compact']:
                    canonical_hex(parts[2])
                    body = (root/(parts[2]+'.bin')).read_bytes()
                    if len(body)>8388656:
                        raise ValueError('Compact response limit.')
                    self.reply(200, body, 'application/octet-stream')
                    return
                elif method == 'POST' and path.path == '/v1/transactions':
                    packet = self.body(657622)
                    if len(packet)<2263 or packet[:4] != b'SWTX' or packet[33:65].hex() != index['network']:
                        raise ValueError('Invalid native transaction framing.')
                    if not self.server.admission:
                        self.reply(503,b'{"error":"Native admission bridge is not configured; no pending acknowledgment."}')
                        return
                    output = subprocess.run([self.server.admission],input=packet,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=45,check=True).stdout
                    if len(output)>2000:
                        raise ValueError('Admission response limit.')
                    result=json.loads(output)
                    if set(result)!={'status','statement_id'} or result['status']!='pending':
                        raise ValueError('Native admission did not acknowledge pending.')
                    canonical_hex(result['statement_id'])
                else:
                    raise ValueError('Unknown public resource.')
            self.reply(200,json.dumps(result,separators=(',',':')).encode())
        except Exception:
            # Do not export exceptions carrying filesystem paths or addresses.
            self.reply(400,b'{"error":"Request rejected; existing durable state was preserved."}')

    def do_GET(self): self.handle_request('GET')
    def do_POST(self): self.handle_request('POST')
    def do_PUT(self): self.handle_request('PUT')

class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16
    def __init__(self, *args, **kwargs):
        self.capacity = threading.BoundedSemaphore(8)
        super().__init__(*args, **kwargs)
    def process_request(self, request, client_address):
        if not self.capacity.acquire(blocking=False):
            self.shutdown_request(request)
            return
        request.settimeout(30)
        try:
            super().process_request(request, client_address)
        except Exception:
            self.capacity.release()
            raise
    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.capacity.release()
    def handle_error(self, *_): pass

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role',choices=['chain','vault'],required=True)
    parser.add_argument('--port',type=int,required=True)
    parser.add_argument('--origin',required=True)
    parser.add_argument('--data',type=Path,required=True)
    parser.add_argument('--admission-program')
    parser.add_argument('--native-socket')
    args=parser.parse_args()
    if not args.origin.startswith(('http://localhost:','https://')) or args.data.is_symlink():
        parser.error('Use an exact application origin and an explicit data directory.')
    args.data.mkdir(parents=True,exist_ok=True)
    server=Server(('localhost',args.port),Handler)
    server.native_socket=args.native_socket
    server.origin,server.role,server.data,server.admission=args.origin,args.role,args.data,args.admission_program
    if args.role=='vault':server.store=VaultStore(str(args.data/'ciphertext.sqlite'),f'http://localhost:{args.port}')
    server.serve_forever()

if __name__=='__main__':main()
