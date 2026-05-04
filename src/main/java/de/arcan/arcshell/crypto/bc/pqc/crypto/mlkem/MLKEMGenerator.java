package de.arcan.arcshell.crypto.bc.pqc.crypto.mlkem;

import java.security.SecureRandom;

import de.arcan.arcshell.crypto.bc.crypto.EncapsulatedSecretGenerator;
import de.arcan.arcshell.crypto.bc.crypto.SecretWithEncapsulation;
import de.arcan.arcshell.crypto.bc.crypto.params.AsymmetricKeyParameter;
import de.arcan.arcshell.crypto.bc.pqc.crypto.util.SecretWithEncapsulationImpl;

public class MLKEMGenerator
    implements EncapsulatedSecretGenerator
{
    // the source of randomness
    private final SecureRandom sr;

    public MLKEMGenerator(SecureRandom random)
    {
        this.sr = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        MLKEMPublicKeyParameters key = (MLKEMPublicKeyParameters)recipientKey;
        MLKEMEngine engine = key.getParameters().getEngine();
        engine.init(sr);

        byte[] randBytes = new byte[32];
        engine.getRandomBytes(randBytes);

        byte[][] kemEncrypt = engine.kemEncrypt(key.getEncoded(), randBytes);
        return new SecretWithEncapsulationImpl(kemEncrypt[0], kemEncrypt[1]);
    }
    public SecretWithEncapsulation internalGenerateEncapsulated(AsymmetricKeyParameter recipientKey, byte[] randBytes)
    {
        MLKEMPublicKeyParameters key = (MLKEMPublicKeyParameters)recipientKey;
        MLKEMEngine engine = key.getParameters().getEngine();
        engine.init(sr);

        byte[][] kemEncrypt = engine.kemEncryptInternal(key.getEncoded(), randBytes);
        return new SecretWithEncapsulationImpl(kemEncrypt[0], kemEncrypt[1]);
    }
}
