package de.arcan.arcshell.crypto.bc.crypto.signers;

import de.arcan.arcshell.crypto.bc.crypto.CipherParameters;
import de.arcan.arcshell.crypto.bc.crypto.CryptoServiceProperties;
import de.arcan.arcshell.crypto.bc.crypto.CryptoServicePurpose;
import de.arcan.arcshell.crypto.bc.crypto.constraints.DefaultServiceProperties;

class Utils
{
    static CryptoServiceProperties getDefaultProperties(String algorithm, int bitsOfSecurity, CipherParameters k, boolean forSigning)
    {
        return new DefaultServiceProperties(algorithm, bitsOfSecurity, k, getPurpose(forSigning));
    }

    static CryptoServicePurpose getPurpose(boolean forSigning)
    {
        return forSigning ? CryptoServicePurpose.SIGNING : CryptoServicePurpose.VERIFYING;
    }
}
