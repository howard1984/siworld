import {ENGINEERING} from './network.js';
import {createEng2Custody} from './eng2-custody-storage.js';
export const {FORMAT,MAX_BACKUP,DB_NAME,parseBackup,backup,bytes,records,save,selectedWallet,savedWalletLabel}=createEng2Custody(ENGINEERING);
