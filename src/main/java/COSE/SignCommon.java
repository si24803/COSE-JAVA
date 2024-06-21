/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

/**
 *
 * @author jimsch
 */

public abstract class SignCommon extends Message {
    protected String contextString;

    byte[] computeSignature(byte[] rgbToBeSigned, OneKey cnKey) throws CoseException {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        return computeSignature(alg, rgbToBeSigned, cnKey, (String) null);
    }

    static byte[] computeSignature(AlgorithmID alg, byte[] rgbToBeSigned, OneKey cnKey)
            throws CoseException {
        String algName = null;
        int sigLen = 0;

        String provider = null;
        switch (alg) {
            case ECDSA_256:
                algName = "SHA256withECDSA";
                sigLen = 32;
                break;
            case ECDSA_384:
                algName = "SHA384withECDSA";
                sigLen = 48;
                break;
            case ECDSA_512:
                algName = "SHA512withECDSA";
                sigLen = 66;
                break;
            case EDDSA:
                algName = "NonewithEdDSA";
                provider = "EdDSA";
                break;

            case RSA_PSS_256:
                algName = "SHA256withRSA/PSS";
                break;

            case RSA_PSS_384:
                algName = "SHA384withRSA/PSS";
                break;

            case RSA_PSS_512:
                algName = "SHA512withRSA/PSS";
                break;

            default:
                throw new CoseException("Unsupported Algorithm Specified");
        }

        if (cnKey == null) {
            throw new NullPointerException();
        }

        PrivateKey privKey = cnKey.AsPrivateKey();
        if (privKey == null) {
            throw new CoseException("Private key required to sign");
        }

        return computeSignature(privKey, rgbToBeSigned, sigLen, algName, provider);
    }

    private static byte[] convertDerToConcat(byte[] der, int len) throws CoseException {
        // this is far too naive
        byte[] concat = new byte[len * 2];

        // assumes SEQUENCE is organized as "R + S"
        int kLen = 4;
        if (der[0] != 0x30) {
            throw new CoseException("Unexpected signature input");
        }
        if ((der[1] & 0x80) != 0) {
            // offset actually 4 + (7-bits of byte 1)
            kLen = 4 + (der[1] & 0x7f);
        }

        // calculate start/end of R
        int rOff = kLen;
        int rLen = der[rOff - 1];
        int rPad = 0;
        if (rLen > len) {
            rOff += (rLen - len);
            rLen = len;
        } else {
            rPad = (len - rLen);
        }
        // copy R
        System.arraycopy(der, rOff, concat, rPad, rLen);

        // calculate start/end of S
        int sOff = rOff + rLen + 2;
        int sLen = der[sOff - 1];
        int sPad = 0;
        if (sLen > len) {
            sOff += (sLen - len);
            sLen = len;
        } else {
            sPad = (len - sLen);
        }
        // copy S
        System.arraycopy(der, sOff, concat, len + sPad, sLen);

        return concat;
    }

    boolean validateSignature(byte[] rgbToBeSigned, byte[] rgbSignature, OneKey cnKey)
            throws CoseException {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        return validateSignature(alg, rgbToBeSigned, rgbSignature, cnKey, (String) null);
    }

    static boolean validateSignature(AlgorithmID alg, byte[] rgbToBeSigned, byte[] rgbSignature, OneKey cnKey)
            throws CoseException {
        String algName = null;
        boolean convert = false;

        String provider = null;
        switch (alg) {
            case ECDSA_256:
                algName = "SHA256withECDSA";
                convert = true;
                break;
            case ECDSA_384:
                algName = "SHA384withECDSA";
                convert = true;
                break;
            case ECDSA_512:
                algName = "SHA512withECDSA";
                convert = true;
                break;

            case EDDSA:
                algName = "NonewithEdDSA";
                provider = "EdDSA";
                break;

            case RSA_PSS_256:
                algName = "SHA256withRSA/PSS";
                break;

            case RSA_PSS_384:
                algName = "SHA384withRSA/PSS";
                break;

            case RSA_PSS_512:
                algName = "SHA512withRSA/PSS";
                break;

            default:
                throw new CoseException("Unsupported Algorithm Specified");
        }

        if (cnKey == null) {
            throw new NullPointerException();
        }

        PublicKey pubKey = cnKey.AsPublicKey();
        if (pubKey == null) {
            throw new CoseException("Public key required to verify");
        }

        if (convert) {
            rgbSignature = convertConcatToDer(rgbSignature);
        }

        return validateSignature(pubKey, algName, rgbToBeSigned, rgbSignature, provider);
    }

    private static byte[] convertConcatToDer(byte[] concat) throws CoseException {
        int len = concat.length / 2;
        byte[] r = Arrays.copyOfRange(concat, 0, len);
        byte[] s = Arrays.copyOfRange(concat, len, concat.length);

        return ASN1.EncodeSignature(r, s);
    }

    // New code to support specifying crypto provider by String (if installed) or
    // Provider (if not installed)

    byte[] computeSignature(byte[] rgbToBeSigned, OneKey cnKey, String provider) throws CoseException {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        return computeSignature(alg, rgbToBeSigned, cnKey, provider);
    }

    static byte[] computeSignature(AlgorithmID alg, byte[] rgbToBeSigned, OneKey cnKey, String provider)
            throws CoseException {
        String algName = null;
        int sigLen = 0;

        switch (alg) {
            case ECDSA_256:
                algName = "SHA256withECDSA";
                sigLen = 32;
                break;
            case ECDSA_384:
                algName = "SHA384withECDSA";
                sigLen = 48;
                break;
            case ECDSA_512:
                algName = "SHA512withECDSA";
                sigLen = 66;
                break;
            case EDDSA:
                algName = "NonewithEdDSA";
                // provider = "EdDSA";
                break;

            case RSA_PSS_256:
                algName = "SHA256withRSA/PSS";
                break;

            case RSA_PSS_384:
                algName = "SHA384withRSA/PSS";
                break;

            case RSA_PSS_512:
                algName = "SHA512withRSA/PSS";
                break;

            default:
                throw new CoseException("Unsupported Algorithm Specified");
        }

        if (cnKey == null) {
            throw new NullPointerException();
        }

        PrivateKey privKey = cnKey.AsPrivateKey();
        if (privKey == null) {
            throw new CoseException("Private key required to sign");
        }

        return computeSignature(privKey, rgbToBeSigned, sigLen, algName, provider);
    }

    byte[] computeSignature(byte[] rgbToBeSigned, OneKey cnKey, Provider provider) throws CoseException {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        return computeSignature(alg, rgbToBeSigned, cnKey, provider);
    }

    static byte[] computeSignature(AlgorithmID alg, byte[] rgbToBeSigned, OneKey cnKey, Provider provider)
            throws CoseException {
        String algName = null;
        int sigLen = 0;

        switch (alg) {
            case ECDSA_256:
                algName = "SHA256withECDSA";
                sigLen = 32;
                break;
            case ECDSA_384:
                algName = "SHA384withECDSA";
                sigLen = 48;
                break;
            case ECDSA_512:
                algName = "SHA512withECDSA";
                sigLen = 66;
                break;
            case EDDSA:
                algName = "NonewithEdDSA";
                // provider = "EdDSA";
                break;

            case RSA_PSS_256:
                algName = "SHA256withRSA/PSS";
                break;

            case RSA_PSS_384:
                algName = "SHA384withRSA/PSS";
                break;

            case RSA_PSS_512:
                algName = "SHA512withRSA/PSS";
                break;

            default:
                throw new CoseException("Unsupported Algorithm Specified");
        }

        if (cnKey == null) {
            throw new NullPointerException();
        }

        PrivateKey privKey = cnKey.AsPrivateKey();
        if (privKey == null) {
            throw new CoseException("Private key required to sign");
        }

        return computeSignature(privKey, rgbToBeSigned, sigLen, algName, provider);
    }

    /**
     * Computes a signature specifying a {@link java.security.Provider} by name.
     * Provider must be installed.
     * 
     * @param algName       Signature algorithm name
     * @param provider      The {@link java.security.Provider}'s name to use for
     *                      signature computation.
     * @param privKey       The private key to compute the signature with.
     * @param rgbToBeSigned Original bytes
     * 
     * @return The computed signature.
     * @throws CoseException if the signature computation cannot be performed
     */
    private static byte[] computeSignature(PrivateKey privKey, byte[] rgbToBeSigned,
            int sigLen, String algName, String provider) throws CoseException {
        byte[] result = null;
        try {
            Signature sig = provider == null ? Signature.getInstance(algName)
                    : Signature.getInstance(algName, provider);
            sig.initSign(privKey);
            sig.update(rgbToBeSigned);
            result = sig.sign();
            if (sigLen > 0) {
                result = convertDerToConcat(result, sigLen);
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Signature failure", ex);
        }

        return result;
    }

    /**
     * Computes a signature specifying a {@link java.security.Provider}. Provider
     * must be installed.
     * 
     * @param algName       Signature algorithm name
     * @param provider      The {@link java.security.Provider} to use for
     *                      signature computation.
     * @param privKey       The private key to compute the signature with.
     * @param rgbToBeSigned Original bytes
     * 
     * @return The computed signature.
     * @throws CoseException if the signature computation cannot be performed
     */
    private static byte[] computeSignature(PrivateKey privKey, byte[] rgbToBeSigned,
            int sigLen, String algName, Provider provider) throws CoseException {
        byte[] result = null;
        try {
            Signature sig = provider == null ? Signature.getInstance(algName)
                    : Signature.getInstance(algName, provider);
            sig.initSign(privKey);
            sig.update(rgbToBeSigned);
            result = sig.sign();
            if (sigLen > 0) {
                result = convertDerToConcat(result, sigLen);
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Signature failure", ex);
        }

        return result;
    }

    boolean validateSignature(byte[] rgbToBeSigned, byte[] rgbSignature, OneKey cnKey, String provider)
            throws CoseException {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        return validateSignature(alg, rgbToBeSigned, rgbSignature, cnKey, provider);
    }

    static boolean validateSignature(AlgorithmID alg, byte[] rgbToBeSigned, byte[] rgbSignature, OneKey cnKey,
            String provider)
            throws CoseException {
        String algName = null;
        boolean convert = false;

        switch (alg) {
            case ECDSA_256:
                algName = "SHA256withECDSA";
                convert = true;
                break;
            case ECDSA_384:
                algName = "SHA384withECDSA";
                convert = true;
                break;
            case ECDSA_512:
                algName = "SHA512withECDSA";
                convert = true;
                break;

            case EDDSA:
                algName = "NonewithEdDSA";
                // provider = "EdDSA";
                break;

            case RSA_PSS_256:
                algName = "SHA256withRSA/PSS";
                break;

            case RSA_PSS_384:
                algName = "SHA384withRSA/PSS";
                break;

            case RSA_PSS_512:
                algName = "SHA512withRSA/PSS";
                break;

            default:
                throw new CoseException("Unsupported Algorithm Specified");
        }

        if (cnKey == null) {
            throw new NullPointerException();
        }

        PublicKey pubKey = cnKey.AsPublicKey();
        if (pubKey == null) {
            throw new CoseException("Public key required to verify");
        }

        if (convert) {
            rgbSignature = convertConcatToDer(rgbSignature);
        }

        return validateSignature(pubKey, algName, rgbToBeSigned, rgbSignature, provider);
    }

    boolean validateSignature(byte[] rgbToBeSigned, byte[] rgbSignature, OneKey cnKey, Provider provider)
            throws CoseException {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        return validateSignature(alg, rgbToBeSigned, rgbSignature, cnKey, provider);
    }

    static boolean validateSignature(AlgorithmID alg, byte[] rgbToBeSigned, byte[] rgbSignature, OneKey cnKey,
            Provider provider)
            throws CoseException {
        String algName = null;
        boolean convert = false;

        switch (alg) {
            case ECDSA_256:
                algName = "SHA256withECDSA";
                convert = true;
                break;
            case ECDSA_384:
                algName = "SHA384withECDSA";
                convert = true;
                break;
            case ECDSA_512:
                algName = "SHA512withECDSA";
                convert = true;
                break;

            case EDDSA:
                algName = "NonewithEdDSA";
                // provider = "EdDSA";
                break;

            case RSA_PSS_256:
                algName = "SHA256withRSA/PSS";
                break;

            case RSA_PSS_384:
                algName = "SHA384withRSA/PSS";
                break;

            case RSA_PSS_512:
                algName = "SHA512withRSA/PSS";
                break;

            default:
                throw new CoseException("Unsupported Algorithm Specified");
        }

        if (cnKey == null) {
            throw new NullPointerException();
        }

        PublicKey pubKey = cnKey.AsPublicKey();
        if (pubKey == null) {
            throw new CoseException("Public key required to verify");
        }

        if (convert) {
            rgbSignature = convertConcatToDer(rgbSignature);
        }

        return validateSignature(pubKey, algName, rgbToBeSigned, rgbSignature, provider);
    }

    /**
     * Validates a signature specifying a {@link java.security.Provider} by name.
     * Provider must be installed.
     * 
     * @param pubKey        Public key to verify the signature with
     * @param algName       Signature algorithm name
     * @param rgbToBeSigned Original bytes
     * @param rgbSignature  Signed bytes
     * @param provider      The {@link java.security.Provider}'s name to use for
     *                      signature
     *                      validation.
     * @return
     * @throws CoseException if the signature validation cannot be performed
     */
    private static boolean validateSignature(PublicKey pubKey, String algName, byte[] rgbToBeSigned,
            byte[] rgbSignature,
            String provider) throws CoseException {
        boolean result = false;
        try {
            Signature sig = provider == null ? Signature.getInstance(algName)
                    : Signature.getInstance(algName, provider);
            sig.initVerify(pubKey);
            sig.update(rgbToBeSigned);

            result = sig.verify(rgbSignature);
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Signature verification failure", ex);
        }

        return result;
    }

    /**
     * Validates a signature specifying a {@link java.security.Provider} by
     * instance.
     * Provider needs not to be installed.
     * 
     * @param pubKey        Public key to verify the signature with
     * @param algName       Signature algorithm name
     * @param rgbToBeSigned Original bytes
     * @param rgbSignature  Signed bytes
     * @param provider      The {@link java.security.Provider} to use for signature
     *                      validation.
     * @return
     * @throws CoseException
     */
    private static boolean validateSignature(PublicKey pubKey, String algName, byte[] rgbToBeSigned,
            byte[] rgbSignature,
            Provider provider) throws CoseException {
        boolean result = false;
        try {
            Signature sig = provider == null ? Signature.getInstance(algName)
                    : Signature.getInstance(algName, provider);
            sig.initVerify(pubKey);
            sig.update(rgbToBeSigned);

            result = sig.verify(rgbSignature);
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Signature verification failure", ex);
        }

        return result;
    }

}
