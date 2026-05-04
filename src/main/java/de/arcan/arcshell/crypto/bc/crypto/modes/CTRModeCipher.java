package de.arcan.arcshell.crypto.bc.crypto.modes;

import de.arcan.arcshell.crypto.bc.crypto.BlockCipher;
import de.arcan.arcshell.crypto.bc.crypto.MultiBlockCipher;
import de.arcan.arcshell.crypto.bc.crypto.SkippingStreamCipher;

public interface CTRModeCipher
    extends MultiBlockCipher, SkippingStreamCipher
{
    /**
     * return the underlying block cipher that we are wrapping.
     *
     * @return the underlying block cipher that we are wrapping.
     */
    BlockCipher getUnderlyingCipher();
}
