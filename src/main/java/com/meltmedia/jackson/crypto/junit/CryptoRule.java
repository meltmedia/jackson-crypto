package com.meltmedia.jackson.crypto.junit;

import javax.validation.Validator;
import javax.validation.ValidatorFactory;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.meltmedia.jackson.crypto.CryptoModule;
import com.meltmedia.jackson.crypto.Defaults;
import com.meltmedia.jackson.crypto.EncryptionService;
import com.meltmedia.jackson.crypto.Functions;
import com.meltmedia.jackson.crypto.Salts;

public class CryptoRule implements TestRule {
  
  public static interface MapperOps {
    public void ops( ObjectMapper mapper );
  }

  public static class Builder {
    private String environmentVariable;
    private MapperOps mixins;
    private ObjectMapper mapper;
    private Validator validator;

    public Builder withEnvironmentVariable(String environmentVariable ) {
      this.environmentVariable = environmentVariable;
      return this;
    }
    
    public Builder withMixins(MapperOps mixins) {
      this.mixins = mixins;
      return this;
    }
    
    public Builder withMapper( ObjectMapper mapper ) {
      this.mapper = mapper;
      return this;
    }
    
    public Builder withValidator( Validator validator ) {
      this.validator = validator;
      return this;
    }

    public CryptoRule build() {
      return new CryptoRule(environmentVariable, mixins, mapper, validator);
    }
  }
  
  private String environmentVariable;
  private MapperOps mixins;
  private ObjectMapper mapper;
  private Validator validator;
  private EncryptionService defaultService;
  private CryptoModule module;
  
  public CryptoRule(String environmentVariable, MapperOps mixins, ObjectMapper mapper, Validator validator) {
    this.environmentVariable = environmentVariable;
    this.mixins = mixins;
    this.mapper = mapper;
    this.validator = validator;
  }
  
  public EncryptionService getService() {
    return defaultService;
  }

  @Override
  public Statement apply(final Statement base, Description description) {
    return new Statement() {

      @Override
      public void evaluate() throws Throwable {
        defaultService =
            EncryptionService.builder()
                .withName(Defaults.DEFAULT_NAME)
                .withObjectMapper(mapper)
                .withValidator(validator)
                .withPassphraseLookup(Functions.passphraseFunction(environmentVariable))
                .withSaltSupplier(Salts.saltSupplier()).build();
        
        // register the service with the object mapper.
        module = new CryptoModule().addSource(defaultService);
        mapper.registerModule(module);

        // add any mixins for the configuration file.
        mixins.ops(mapper);

        base.evaluate();
      }
      
    };
  }

}
