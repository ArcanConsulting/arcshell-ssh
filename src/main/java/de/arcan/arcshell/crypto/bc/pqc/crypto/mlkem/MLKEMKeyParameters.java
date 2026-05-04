package de.arcan.arcshell.crypto.bc.pqc.crypto.mlkem;

import de.arcan.arcshell.crypto.bc.crypto.params.AsymmetricKeyParameter;

public class MLKEMKeyParameters
    extends AsymmetricKeyParameter
{
    private MLKEMParameters params;

    public MLKEMKeyParameters(
        boolean isPrivate,
        MLKEMParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public MLKEMParameters getParameters()
    {
        return params;
    }

}
