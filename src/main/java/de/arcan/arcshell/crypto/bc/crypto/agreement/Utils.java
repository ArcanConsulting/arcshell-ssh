package de.arcan.arcshell.crypto.bc.crypto.agreement;

import de.arcan.arcshell.crypto.bc.crypto.CryptoServiceProperties;
import de.arcan.arcshell.crypto.bc.crypto.CryptoServicePurpose;
import de.arcan.arcshell.crypto.bc.crypto.constraints.DefaultServiceProperties;
import de.arcan.arcshell.crypto.bc.crypto.params.X25519PrivateKeyParameters;

class Utils
{
    static CryptoServiceProperties getDefaultProperties(String algorithm, X25519PrivateKeyParameters k)
    {
        return new DefaultServiceProperties(algorithm, 128, k, CryptoServicePurpose.AGREEMENT);
    }
}
