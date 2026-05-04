package de.arcan.arcshell.crypto.bc.crypto.agreement;

import de.arcan.arcshell.crypto.bc.crypto.CipherParameters;
import de.arcan.arcshell.crypto.bc.crypto.CryptoServicesRegistrar;
import de.arcan.arcshell.crypto.bc.crypto.RawAgreement;
import de.arcan.arcshell.crypto.bc.crypto.params.X25519PrivateKeyParameters;
import de.arcan.arcshell.crypto.bc.crypto.params.X25519PublicKeyParameters;

public final class X25519Agreement
    implements RawAgreement
{
    private X25519PrivateKeyParameters privateKey;

    public void init(CipherParameters parameters)
    {
        this.privateKey = (X25519PrivateKeyParameters)parameters;

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("X25519", this.privateKey));
    }

    public int getAgreementSize()
    {
        return X25519PrivateKeyParameters.SECRET_SIZE;
    }

    public void calculateAgreement(CipherParameters publicKey, byte[] buf, int off)
    {
        privateKey.generateSecret((X25519PublicKeyParameters)publicKey, buf, off);
    }
}
