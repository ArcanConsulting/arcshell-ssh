package de.arcan.arcshell.crypto.bc.crypto.params;

import java.security.SecureRandom;

import de.arcan.arcshell.crypto.bc.crypto.KeyGenerationParameters;

public class Ed25519KeyGenerationParameters
    extends KeyGenerationParameters
{
    public Ed25519KeyGenerationParameters(SecureRandom random)
    {
        super(random, 256);
    }
}
