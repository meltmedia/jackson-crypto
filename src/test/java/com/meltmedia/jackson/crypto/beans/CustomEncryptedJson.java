
package com.meltmedia.jackson.crypto.beans;

import java.util.HashMap;
import java.util.Map;
import javax.annotation.Generated;
import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;


/**
 * An ecrypted block of JSON.
 * 
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Generated("org.jsonschema2pojo")
@JsonPropertyOrder({
    "salt",
    "iv",
    "value",
    "cipher",
    "keyDerivation",
    "keyLength",
    "iterations",
    "keyName"
})
public class CustomEncryptedJson {

    /**
     * The salt used to encrypt this value.
     * 
     */
    @JsonProperty("salt")
    private byte[] salt;
    /**
     * The initialization vector used to encrypt this value.
     * 
     */
    @JsonProperty("iv")
    private byte[] iv;
    /**
     * The value, either encrypted or decrypted, based on the encrypted flag.
     * 
     */
    @JsonProperty("value")
    private byte[] value;
    /**
     * The cipher used to encrypt this value.
     * 
     */
    @JsonProperty("cipher")
    private String cipher;
    /**
     * The key derivation function.
     * 
     */
    @JsonProperty("keyDerivation")
    private String keyDerivation;
    /**
     * The length of the key used to encrypt this value.
     * 
     */
    @JsonProperty("keyLength")
    private Integer keyLength;
    /**
     * The number of key streching iterations used during encryption.
     * 
     */
    @JsonProperty("iterations")
    private Integer iterations;
    /**
     * The name of the key for this data.  If missing, the data was encrypted with a statically defined key.
     * 
     */
    @JsonProperty("keyName")
    private String keyName;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    /**
     * The salt used to encrypt this value.
     * 
     */
    @JsonProperty("salt")
    public byte[] getSalt() {
        return salt;
    }

    /**
     * The salt used to encrypt this value.
     * 
     */
    @JsonProperty("salt")
    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    public CustomEncryptedJson withSalt(byte[] salt) {
        this.salt = salt;
        return this;
    }

    /**
     * The initialization vector used to encrypt this value.
     * 
     */
    @JsonProperty("iv")
    public byte[] getIv() {
        return iv;
    }

    /**
     * The initialization vector used to encrypt this value.
     * 
     */
    @JsonProperty("iv")
    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public CustomEncryptedJson withIv(byte[] iv) {
        this.iv = iv;
        return this;
    }

    /**
     * The value, either encrypted or decrypted, based on the encrypted flag.
     * 
     */
    @JsonProperty("value")
    public byte[] getValue() {
        return value;
    }

    /**
     * The value, either encrypted or decrypted, based on the encrypted flag.
     * 
     */
    @JsonProperty("value")
    public void setValue(byte[] value) {
        this.value = value;
    }

    public CustomEncryptedJson withValue(byte[] value) {
        this.value = value;
        return this;
    }

    /**
     * The cipher used to encrypt this value.
     * 
     */
    @JsonProperty("cipher")
    public String getCipher() {
        return cipher;
    }

    /**
     * The cipher used to encrypt this value.
     * 
     */
    @JsonProperty("cipher")
    public void setCipher(String cipher) {
        this.cipher = cipher;
    }

    public CustomEncryptedJson withCipher(String cipher) {
        this.cipher = cipher;
        return this;
    }

    /**
     * The key derivation function.
     * 
     */
    @JsonProperty("keyDerivation")
    public String getKeyDerivation() {
        return keyDerivation;
    }

    /**
     * The key derivation function.
     * 
     */
    @JsonProperty("keyDerivation")
    public void setKeyDerivation(String keyDerivation) {
        this.keyDerivation = keyDerivation;
    }

    public CustomEncryptedJson withKeyDerivation(String keyDerivation) {
        this.keyDerivation = keyDerivation;
        return this;
    }

    /**
     * The length of the key used to encrypt this value.
     * 
     */
    @JsonProperty("keyLength")
    public Integer getKeyLength() {
        return keyLength;
    }

    /**
     * The length of the key used to encrypt this value.
     * 
     */
    @JsonProperty("keyLength")
    public void setKeyLength(Integer keyLength) {
        this.keyLength = keyLength;
    }

    public CustomEncryptedJson withKeyLength(Integer keyLength) {
        this.keyLength = keyLength;
        return this;
    }

    /**
     * The number of key streching iterations used during encryption.
     * 
     */
    @JsonProperty("iterations")
    public Integer getIterations() {
        return iterations;
    }

    /**
     * The number of key streching iterations used during encryption.
     * 
     */
    @JsonProperty("iterations")
    public void setIterations(Integer iterations) {
        this.iterations = iterations;
    }

    public CustomEncryptedJson withIterations(Integer iterations) {
        this.iterations = iterations;
        return this;
    }

    /**
     * The name of the key for this data.  If missing, the data was encrypted with a statically defined key.
     * 
     */
    @JsonProperty("keyName")
    public String getKeyName() {
        return keyName;
    }

    /**
     * The name of the key for this data.  If missing, the data was encrypted with a statically defined key.
     * 
     */
    @JsonProperty("keyName")
    public void setKeyName(String keyName) {
        this.keyName = keyName;
    }

    public CustomEncryptedJson withKeyName(String keyName) {
        this.keyName = keyName;
        return this;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

    @Override
    public boolean equals(Object other) {
        return EqualsBuilder.reflectionEquals(this, other);
    }

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

    public CustomEncryptedJson withAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
        return this;
    }

}
