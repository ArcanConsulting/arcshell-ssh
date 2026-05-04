package de.arcan.arcshell.crypto.bc.crypto.util;

import de.arcan.arcshell.crypto.bc.crypto.Digest;
import de.arcan.arcshell.crypto.bc.crypto.digests.SHA1Digest;
import de.arcan.arcshell.crypto.bc.crypto.digests.SHA256Digest;
import de.arcan.arcshell.crypto.bc.crypto.digests.SHA3Digest;
import de.arcan.arcshell.crypto.bc.crypto.digests.SHA512Digest;
import de.arcan.arcshell.crypto.bc.crypto.digests.SHAKEDigest;

public final class DigestFactory
{
    public static Digest createSHA1()
    {
        return new SHA1Digest();
    }

    public static Digest createSHA256()
    {
        return SHA256Digest.newInstance();
    }

    public static Digest createSHA512()
    {
        return new SHA512Digest();
    }

    public static Digest createSHA3_256()
    {
        return new SHA3Digest(256);
    }

    public static Digest createSHA3_512()
    {
        return new SHA3Digest(512);
    }

    public static Digest createSHAKE128()
    {
        return new SHAKEDigest(128);
    }

    public static Digest createSHAKE256()
    {
        return new SHAKEDigest(256);
    }
}
