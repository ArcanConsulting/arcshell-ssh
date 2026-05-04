package de.arcan.arcshell.crypto.bc.crypto;

public interface CryptoServiceProperties
{
    int bitsOfSecurity();

    String getServiceName();

    CryptoServicePurpose getPurpose();

    Object getParams();
}
