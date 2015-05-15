package com.novaordis.security.cryptography;


import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class CipherSpiImpl extends CipherSpi

{
    // Constants -------------------------------------------------------------------------------------------------------

    // Static ----------------------------------------------------------------------------------------------------------

    // Attributes ------------------------------------------------------------------------------------------------------

    // Constructors ----------------------------------------------------------------------------------------------------

    // CipherSpi overrides ---------------------------------------------------------------------------------------------

    @Override
    protected void engineSetMode(String s) throws NoSuchAlgorithmException
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    protected void engineSetPadding(String s) throws NoSuchPaddingException
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    protected int engineGetBlockSize()
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    protected int engineGetOutputSize(int i)
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    protected byte[] engineGetIV()
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    protected AlgorithmParameters engineGetParameters()
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    protected void engineInit(int i, Key key, SecureRandom secureRandom) throws InvalidKeyException
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    protected void engineInit(int i, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    protected void engineInit(int i, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    protected byte[] engineUpdate(byte[] bytes, int i, int i2)
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    protected int engineUpdate(byte[] bytes, int i, int i2, byte[] bytes2, int i3) throws ShortBufferException
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    protected byte[] engineDoFinal(byte[] bytes, int i, int i2) throws IllegalBlockSizeException, BadPaddingException
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    @Override
    protected int engineDoFinal(byte[] bytes, int i, int i2, byte[] bytes2, int i3) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        throw new RuntimeException("NOT YET IMPLEMENTED");
    }

    // Public ----------------------------------------------------------------------------------------------------------

    // Package protected -----------------------------------------------------------------------------------------------

    // Protected -------------------------------------------------------------------------------------------------------

    // Private ---------------------------------------------------------------------------------------------------------

    // Inner classes ---------------------------------------------------------------------------------------------------

}
