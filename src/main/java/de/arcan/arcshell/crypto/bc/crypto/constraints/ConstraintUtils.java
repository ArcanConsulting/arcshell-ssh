package de.arcan.arcshell.crypto.bc.crypto.constraints;

import java.math.BigInteger;

public class ConstraintUtils
{
    /**
     * Return the bits of security for the passed in RSA modulus or DH/DSA group value.
     *
     * @param p a modulus or group value
     * @return the security strength in bits.
     */
    public static int bitsOfSecurityFor(BigInteger p)
    {
        return bitsOfSecurityForFF(p.bitLength());
    }

    public static int bitsOfSecurityForFF(int strength)
    {
        if (strength >= 2048)
        {
            return (strength >= 3072) ?
                        ((strength >= 7680) ?
                            ((strength >= 15360) ? 256
                            : 192)
                        : 128)
                   : 112;
        }

        return (strength >= 1024) ? 80 : 20;
    }
}
