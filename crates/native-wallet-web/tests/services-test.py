"""Authentication, replay, CAS and bounded ciphertext retention tests."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
spec=importlib.util.spec_from_file_location('services',Path(__file__).parents[1]/'tools/engineering-services.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.now=0
        self.store=m.VaultStore(str(Path(self.tmp.name)/'ciphertext.sqlite'),'https://vault.test.invalid',accounts=2,clock=lambda:self.now)
        self.key=Ed25519PrivateKey.generate();self.locator='12'*32
        self.public=self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    def tearDown(self):self.store.db.close();self.tmp.cleanup()
    def headers(self,method,body=b'',revision=0,previous=m.ZERO,locator=None,key=None):
        locator=locator or self.locator;key=key or self.key
        challenge=self.store.challenge(locator,method)['challenge']
        sig=key.sign(m.auth_message(self.store.origin,method,locator,challenge,revision,body,previous)).hex()
        return {'X-Vault-Challenge':challenge,'X-Vault-Signature':sig,'X-Vault-Revision':str(revision),'X-Vault-Previous':previous}
    def enroll(self):return self.store.create(self.locator,self.public,self.headers('POST',self.public))
    def body(self,tag=0):return b'SWVSNP01'+bytes([tag])*(m.SNAPSHOT-8)
    def put(self,body,revision=0,previous=m.ZERO):
        h=self.headers('PUT',body,revision,previous);d=hashlib.sha256(body).hexdigest();h['X-Vault-Record']=self.key.sign(m.revision_message(self.locator,revision+1,d,previous)).hex()
        return self.store.put(self.locator,body,h)
    def test_enrollment_requires_possession_and_never_accepts_private_key(self):
        bad=Ed25519PrivateKey.generate();h=self.headers('POST',self.public,key=bad)
        with self.assertRaises(Exception):self.store.create(self.locator,self.public,h)
        self.assertEqual(self.enroll()['status'],'created')
        self.assertEqual(self.store.db.execute('SELECT key FROM accounts').fetchone()[0],self.public)
    def test_fixed_length_durable_read_and_one_use_challenge(self):
        self.enroll();body=self.body();h=self.headers('PUT',body);d=hashlib.sha256(body).hexdigest();h['X-Vault-Record']=self.key.sign(m.revision_message(self.locator,1,d,m.ZERO)).hex()
        self.assertEqual(self.store.put(self.locator,body,h)['revision'],'1')
        with self.assertRaises(Exception):self.store.put(self.locator,body,h)
        result=self.store.get(self.locator,self.headers('GET',revision=1,previous=d));self.assertEqual(len(result[4]),524288);self.assertEqual(result[4],body)
        for size in [0,524287,524289]:
            with self.assertRaises(Exception):self.store.put(self.locator,bytes(size),{})
    def test_method_body_origin_and_expiry_binding(self):
        self.enroll();body=self.body();h=self.headers('PUT',body)
        with self.assertRaises(Exception):self.store.authenticate('GET',self.locator,b'',h)
        h=self.headers('PUT',body)
        with self.assertRaises(Exception):self.store.authenticate('PUT',self.locator,body[:-1]+b'X',h)
        h=self.headers('GET');self.now=61
        with self.assertRaises(Exception):self.store.get(self.locator,h)
        h=self.headers('GET');self.store.origin='https://other.invalid'
        with self.assertRaises(Exception):self.store.get(self.locator,h)
    def test_conflict_preserves_previous_snapshot_and_retains_three_versions(self):
        self.enroll();d=m.ZERO
        for revision in range(5):
            ack=self.put(self.body(revision),revision,d);d=ack['digest']
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM snapshots').fetchone()[0],3)
        with self.assertRaises(Exception):self.put(self.body(9),0,m.ZERO)
        row=self.store.get(self.locator,self.headers('GET',revision=5,previous=d));self.assertEqual(row[0],5);self.assertEqual(row[2],d)
    def test_account_isolation_and_enrollment_quota(self):
        self.enroll();other='34'*32;h=self.headers('POST',self.public,locator=other);self.store.create(other,self.public,h)
        third='56'*32
        with self.assertRaises(Exception):self.store.create(third,self.public,self.headers('POST',self.public,locator=third))
        self.put(self.body())
        with self.assertRaises(Exception):self.store.get(other,self.headers('GET',locator=other))
    def test_challenges_and_identifiers_are_bounded(self):
        with self.assertRaises(Exception):self.store.challenge('../private','GET')
        for _ in range(128):self.store.challenge(self.locator,'GET')
        with self.assertRaises(Exception):self.store.challenge(self.locator,'GET')
        self.now=61;self.assertIn('challenge',self.store.challenge(self.locator,'GET'))


class ChainHistoryTests(unittest.TestCase):
    def test_pinned_ancestor_remains_readable_as_current_chain_extends(self):
        index={'genesis':'00'*32,'ids':['01'*32,'02'*32,'03'*32]}
        self.assertEqual(m.chain_page(index,'02'*32,1,128),{'ids':['01'*32,'02'*32]})
        self.assertEqual(m.chain_page(index,'02'*32,3,128),{'ids':[]})
        for tip,start,limit in [('04'*32,1,1),('02'*32,4,1),('02'*32,0,1),('02'*32,1,129)]:
            with self.assertRaises(Exception):m.chain_page(index,tip,start,limit)

if __name__=='__main__':unittest.main()
