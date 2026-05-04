package de.arcan.arcshell.crypto.bc.crypto.generators;

import java.security.SecureRandom;

import de.arcan.arcshell.crypto.bc.crypto.AsymmetricCipherKeyPair;
import de.arcan.arcshell.crypto.bc.crypto.AsymmetricCipherKeyPairGenerator;
import de.arcan.arcshell.crypto.bc.crypto.CryptoServicePurpose;
import de.arcan.arcshell.crypto.bc.crypto.CryptoServicesRegistrar;
import de.arcan.arcshell.crypto.bc.crypto.KeyGenerationParameters;
import de.arcan.arcshell.crypto.bc.crypto.constraints.DefaultServiceProperties;
import de.arcan.arcshell.crypto.bc.crypto.params.Ed25519PrivateKeyParameters;
import de.arcan.arcshell.crypto.bc.crypto.params.Ed25519PublicKeyParameters;

public class Ed25519KeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    public void init(KeyGenerationParameters parameters)
    {
        this.random = parameters.getRandom();

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("Ed25519KeyGen", 128, null, CryptoServicePurpose.KEYGEN));
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(random);
        Ed25519PublicKeyParameters publicKey = privateKey.generatePublicKey();
        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
