import {initVault} from './native-vault.js';
import {VAULT} from '../sdk/vault-network.js';
import './cloud-vault.js';
location.hash='#vault';
if(VAULT.wallet_application){const link=document.querySelector('[data-view="wallet"]');link.href=VAULT.wallet_application;link.rel='noreferrer noopener';}
document.querySelector('#status').textContent='Independent Vault · No wallet session or chain submission.';
initVault(()=>null);
