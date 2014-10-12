package com.meltmedia.jackson.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Converts external types into EncryptedConfiguration and EncryptedData types.
 * 
 * The library being used to generate beans from JSON Schema does not provide a good
 * way to bind custom types.  This library is provided to bridge the types in that
 * package with this packages types.
 * 
 * @author Christian Trimble
 *
 */
public class EncyrptedValueConverter {
  ObjectMapper mapper;
  
  public EncyrptedValueConverter() {
    mapper = new ObjectMapper();
  }
  
  public EncryptedConfiguration toEncryptedConfig( Object o ) {
    return mapper.convertValue(o, EncryptedConfiguration.class);
  }
  
  public EncryptedData toEncryptedData( Object o ) {
    return mapper.convertValue(o, EncryptedData.class);
  }
}
