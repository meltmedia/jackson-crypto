package com.meltmedia.jackson.crypto;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.meltmedia.jackson.crypto.beans.DeserAnnotatedWithEncrypted;
import com.meltmedia.jackson.crypto.beans.SerAnnotatedWithEncrypted;
import com.meltmedia.jackson.crypto.beans.WithEncrypted;

public class DecryptWithObjectMapperTest {
	
	ObjectMapper mapper;
	EncryptionService<EncryptedJson> service;
	
	@Before
	public void setUp() {
		  Map<String, char[]> keys = new HashMap<String, char[]>();
			keys.put("current", "current secret".toCharArray());
			keys.put("old", "old secret".toCharArray());
			DynamicEncryptionConfiguration config = new DynamicEncryptionConfiguration();
			config.setCurrentKey("current");
			config.setKeys(keys);
			
	      mapper = new ObjectMapper();
			
	      service = EncryptionService.builder()
	    		  .withPassphraseLookup(config.passphraseFunction())
	    		  .withEncryptedJsonSupplier(config.encryptedJsonSupplier())
	    		  .withObjectMapper(mapper)
	    		  .build();
	      
		  mapper.registerModule(new CryptoModule(service));	
	}

	@Test
	public void shouldRoundTrip() throws IOException {
		WithEncrypted withEncrypted = new WithEncrypted()
		  .withStringValue("some secret");
		
		String value = mapper.writeValueAsString(withEncrypted);
		
		WithEncrypted decrypted = mapper.readValue(value, WithEncrypted.class);
		
		assertThat("the original class and the decrypted class are the same", decrypted, equalTo(withEncrypted));
	}
	
	@Test
	public void shouldDecryptWithDeserializerAnnotation() throws JsonParseException, JsonMappingException, JsonProcessingException, IOException {
		SerAnnotatedWithEncrypted toEncrypt = new SerAnnotatedWithEncrypted()
		  .withValue("some value");
		
		DeserAnnotatedWithEncrypted roundTrip = mapper.readValue(mapper.writeValueAsString(toEncrypt), DeserAnnotatedWithEncrypted.class);

		assertThat(roundTrip.value, equalTo("some value"));
		
	}

}
