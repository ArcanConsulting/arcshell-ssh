package de.arcan.arcshell.crypto.bc.crypto.engines;

import de.arcan.arcshell.crypto.bc.crypto.CryptoServicePurpose;

class Utils
{
    static CryptoServicePurpose getPurpose(boolean forEncryption)
    {
        return forEncryption ? CryptoServicePurpose.ENCRYPTION : CryptoServicePurpose.DECRYPTION;
    }
}
