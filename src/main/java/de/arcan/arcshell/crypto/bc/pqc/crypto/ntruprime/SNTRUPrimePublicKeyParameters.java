package de.arcan.arcshell.crypto.bc.pqc.crypto.ntruprime;

import de.arcan.arcshell.crypto.bc.util.Arrays;

public class SNTRUPrimePublicKeyParameters
    extends SNTRUPrimeKeyParameters
{
    private final byte[] encH;

    public SNTRUPrimePublicKeyParameters(SNTRUPrimeParameters params, byte[] encH)
    {
        super(false, params);
        this.encH = Arrays.clone(encH);
    }

    byte[] getEncH()
    {
        return encH;
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(encH);
    }
}
