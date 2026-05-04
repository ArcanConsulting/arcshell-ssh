package de.arcan.arcshell.crypto.bc.pqc.crypto.ntruprime;

import de.arcan.arcshell.crypto.bc.crypto.params.AsymmetricKeyParameter;

public class SNTRUPrimeKeyParameters
    extends AsymmetricKeyParameter
{
    private final SNTRUPrimeParameters params;

    public SNTRUPrimeKeyParameters(boolean privateKey, SNTRUPrimeParameters params)
    {
        super(privateKey);
        this.params = params;
    }

    public SNTRUPrimeParameters getParameters()
    {
        return params;
    }
}
