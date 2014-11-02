package com.meltmedia.jackson.crypto;

import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializationConfig;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.BeanPropertyWriter;
import com.fasterxml.jackson.databind.ser.BeanSerializerModifier;

public class EncryptedJsonSerializer extends JsonSerializer<Object> {

	private JsonSerializer<Object> baseSer;
	private EncryptionService<EncryptedJson> service;
	private Encrypted annotation;

	public EncryptedJsonSerializer(EncryptionService<EncryptedJson> service, Encrypted annotation, JsonSerializer<Object> baseSer) {
		this.service = service;
		this.annotation = annotation;
		this.baseSer = baseSer;
	}

	@Override
	public void serialize(Object object, JsonGenerator generator, SerializerProvider provider)
	  throws IOException, JsonProcessingException
	{

	    StringWriter writer = new StringWriter();
	    JsonGenerator nestedGenerator = generator.getCodec().getFactory().createGenerator(writer);
	    if( baseSer == null ) {
		  provider.defaultSerializeValue(object, nestedGenerator);
	    }
	    else {
	    	baseSer.serialize(object, nestedGenerator, provider);
	    }
		nestedGenerator.close();
		String value = writer.getBuffer().toString();
      EncryptedJson encrypted = service.encrypt(value, this.annotation.encoding());
      generator.writeObject(encrypted);
	}
	
	public static class Modifier extends BeanSerializerModifier {

		EncryptionService<EncryptedJson> service;
		
		public Modifier( EncryptionService<EncryptedJson> service ) {
			this.service = service;
		}
		
		// we do not need to override this.
		@Override
		public List<BeanPropertyWriter> changeProperties(
				SerializationConfig config, BeanDescription beanDesc,
				List<BeanPropertyWriter> beanProperties) {
			List<BeanPropertyWriter> newWriters = new ArrayList<BeanPropertyWriter>();
			for( BeanPropertyWriter writer : beanProperties ) {
				Encrypted encrypted = writer.getAnnotation(Encrypted.class);
				if( encrypted == null ) {
					newWriters.add(writer);
					continue;
				}

			    JsonSerializer<Object> currentSer = writer.getSerializer();
			    JsonSerializer<Object> encryptSer =  new EncryptedJsonSerializer(service, encrypted, currentSer);
			    newWriters.add(new EncryptedPropertyWriter(writer,encryptSer));
			}
			return newWriters;
		}

	}
	
	static class EncryptedPropertyWriter extends BeanPropertyWriter {

		public EncryptedPropertyWriter( BeanPropertyWriter toCopy, JsonSerializer<Object> deser ) {
			super(toCopy);
			this._serializer = deser;
		}
	}

}
