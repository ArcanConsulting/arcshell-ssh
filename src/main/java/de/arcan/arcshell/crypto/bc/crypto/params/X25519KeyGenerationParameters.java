package de.arcan.arcshell.crypto.bc.crypto.params;

import java.security.SecureRandom;

import de.arcan.arcshell.crypto.bc.crypto.KeyGenerationParameters;

public class X25519KeyGenerationParameters
    extends KeyGenerationParameters
{
    public X25519KeyGenerationParameters(SecureRandom random)
    {
        super(random, 255);
    }
}
