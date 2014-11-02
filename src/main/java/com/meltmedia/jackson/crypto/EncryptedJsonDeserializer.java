package com.meltmedia.jackson.crypto;

import java.io.IOException;
import java.util.Iterator;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.deser.BeanDeserializerBuilder;
import com.fasterxml.jackson.databind.deser.BeanDeserializerModifier;
import com.fasterxml.jackson.databind.deser.ContextualDeserializer;
import com.fasterxml.jackson.databind.deser.SettableBeanProperty;

public class EncryptedJsonDeserializer extends JsonDeserializer<Object> implements ContextualDeserializer {

	private EncryptionService<EncryptedJson> service;
	private JsonDeserializer<Object> baseDeser;
	private Encrypted annotation;
	private BeanProperty property;

	public EncryptedJsonDeserializer(
			EncryptionService<EncryptedJson> service,
			Encrypted annotation,
			JsonDeserializer<Object> baseDeser) {
		this.service = service;
		this.annotation = annotation;
		this.baseDeser = baseDeser;
	}

	public EncryptedJsonDeserializer(
			EncryptionService<EncryptedJson> service,
			Encrypted encrypt,
			JsonDeserializer<Object> wrapped,
			BeanProperty property) {
		this.service = service;
		this.annotation = encrypt;
		this.baseDeser = wrapped;
		this.property = property;
	}

	@Override
	public Object deserialize(JsonParser parser, DeserializationContext context)
			throws IOException, JsonProcessingException {
		EncryptedJson encrypted = parser.readValueAs(EncryptedJson.class);
		String decrypted = service.decrypt(encrypted, annotation.encoding());
		JsonParser decryptedParser = parser.getCodec().getFactory().createParser(decrypted);
		if( baseDeser == null ) {
          return parser.getCodec().readValue(decryptedParser, property.getType());
		}
		else {
			if( baseDeser instanceof ContextualDeserializer ) {
				return ((ContextualDeserializer) baseDeser).createContextual(context, property)
						.deserialize(decryptedParser, context);
			}
			return baseDeser.deserialize(decryptedParser, context);
		}
    }

	@Override
	public JsonDeserializer<?> createContextual(DeserializationContext context,
			BeanProperty property) throws JsonMappingException {
		return new EncryptedJsonDeserializer(service, annotation, baseDeser, property);
	}

	public static class Modifier extends BeanDeserializerModifier {
		private EncryptionService<EncryptedJson> service;
		
		public Modifier(EncryptionService<EncryptedJson> service) {
			this.service = service;
		}
		
		@Override
		public BeanDeserializerBuilder updateBuilder(
				DeserializationConfig config, BeanDescription beanDesc,
				BeanDeserializerBuilder builder) {
			Iterator<SettableBeanProperty> beanPropertyIterator = builder.getProperties();
            while (beanPropertyIterator.hasNext()) {
            	SettableBeanProperty settableBeanProperty = beanPropertyIterator.next();
            	Encrypted encrypted = settableBeanProperty.getAnnotation(Encrypted.class);
            	if( encrypted != null ) {
            		JsonDeserializer<Object> current = settableBeanProperty.getValueDeserializer();
            		builder.addOrReplaceProperty(settableBeanProperty.withValueDeserializer(new EncryptedJsonDeserializer(service, encrypted, current)), true);
            	}
            }
            return builder;
		}

	}
}
