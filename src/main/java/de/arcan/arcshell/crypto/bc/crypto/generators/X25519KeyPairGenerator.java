package de.arcan.arcshell.crypto.bc.crypto.generators;

import java.security.SecureRandom;

import de.arcan.arcshell.crypto.bc.crypto.AsymmetricCipherKeyPair;
import de.arcan.arcshell.crypto.bc.crypto.AsymmetricCipherKeyPairGenerator;
import de.arcan.arcshell.crypto.bc.crypto.CryptoServicePurpose;
import de.arcan.arcshell.crypto.bc.crypto.CryptoServicesRegistrar;
import de.arcan.arcshell.crypto.bc.crypto.KeyGenerationParameters;
import de.arcan.arcshell.crypto.bc.crypto.constraints.DefaultServiceProperties;
import de.arcan.arcshell.crypto.bc.crypto.params.X25519PrivateKeyParameters;
import de.arcan.arcshell.crypto.bc.crypto.params.X25519PublicKeyParameters;

public class X25519KeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    public void init(KeyGenerationParameters parameters)
    {
        this.random = parameters.getRandom();

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("X25519KeyGen", 128, null, CryptoServicePurpose.KEYGEN));
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        X25519PrivateKeyParameters privateKey = new X25519PrivateKeyParameters(random);
        X25519PublicKeyParameters publicKey = privateKey.generatePublicKey();
        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
