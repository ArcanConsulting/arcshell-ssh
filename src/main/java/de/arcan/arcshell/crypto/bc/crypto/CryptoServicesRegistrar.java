package de.arcan.arcshell.crypto.bc.crypto;

import java.security.SecureRandom;

/**
 * Minimal registrar for cryptography services.
 * Simplified for standalone arcshell-crypto module — only provides
 * SecureRandom and no-op constraint checking.
 */
public final class CryptoServicesRegistrar
{
    private static final ThreadLocal<SecureRandom> threadLocalRandom = new ThreadLocal<SecureRandom>();

    private CryptoServicesRegistrar()
    {
    }

    /**
     * Return the default source of randomness.
     *
     * @return the default SecureRandom
     */
    public static SecureRandom getSecureRandom()
    {
        SecureRandom r = threadLocalRandom.get();
        if (r == null)
        {
            r = new SecureRandom();
            threadLocalRandom.set(r);
        }
        return r;
    }

    /**
     * Return either the passed-in SecureRandom, or if it is null, then the default source of randomness.
     *
     * @param secureRandom the SecureRandom to use if it is not null.
     * @return the SecureRandom parameter if it is not null, or else the default SecureRandom
     */
    public static SecureRandom getSecureRandom(SecureRandom secureRandom)
    {
        return null == secureRandom ? getSecureRandom() : secureRandom;
    }

    /**
     * Check a service to make sure it meets the current constraints.
     * This is a no-op in the simplified arcshell-crypto module.
     *
     * @param cryptoService the service to be checked.
     */
    public static void checkConstraints(CryptoServiceProperties cryptoService)
    {
        // no-op — we don't need runtime constraint checking
    }
}
