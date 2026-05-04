package de.arcan.arcshell.crypto.bc.math.ec;

import java.math.BigInteger;

/**
 * Minimal WNafUtil — only provides getNafWeight() for RSA primality testing.
 */
public abstract class WNafUtil
{
    public static int getNafWeight(BigInteger k)
    {
        if (k.signum() == 0)
        {
            return 0;
        }

        BigInteger _3k = k.shiftLeft(1).add(k);
        BigInteger diff = _3k.xor(k);

        return diff.bitCount();
    }
}
