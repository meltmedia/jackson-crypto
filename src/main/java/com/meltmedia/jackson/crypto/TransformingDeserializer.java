package com.meltmedia.jackson.crypto;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.ContextualDeserializer;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

/**
 * A deserializer that transforms values as they are deserialized.
 * 
 * @author Christian Trimble
 *
 * @param <I> the type that the value is deserialized into before being transformed.
 */
@SuppressWarnings("serial")
public abstract class TransformingDeserializer<I>
  extends StdDeserializer<Object> implements ContextualDeserializer {

  protected Class<I> intermediateType;
  protected JavaType targetType;
  protected BeanProperty property;

  protected TransformingDeserializer( Class<I> intermediateType ) {
    super(Object.class);
    this.intermediateType = intermediateType;
  }

  protected TransformingDeserializer( Class<I> intermediateType, BeanProperty property ) {
    super(Object.class);
    this.intermediateType = intermediateType;
    this.property = property;
    this.targetType = property.getType();
  }

  @Override
  public Object deserialize( JsonParser jp, DeserializationContext ctxt ) throws IOException, JsonProcessingException {
    ObjectMapper mapper = objectMapper(jp);
    I intermediate = mapper.readValue(jp, intermediateType);
    return transform(intermediate, mapper, ctxt);
  }

  /**
   * Creates a new version of this deserializer with the type of the property.  If subclasses do not override this method,
   * then they must provide a public single argument constructor that takes JavaType.
   */
  @SuppressWarnings("unchecked")
  @Override
  public TransformingDeserializer<?> createContextual( DeserializationContext ctxt, BeanProperty property ) throws JsonMappingException {
    try {
      return (TransformingDeserializer<I>) this.getClass().getConstructor(BeanProperty.class).newInstance(property);
    } catch( InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException | NoSuchMethodException | SecurityException e ) {
      throw new JsonMappingException("Transforming deserializers require a public contructor that takes JavaType as its only argument.", e);
    }
  }

  /**
   * Transforms the intermediate type into the target type.
   * 
   * @param intermediate the intermediate value deserialized from the input.
   * @param mapper an object mapper that was created from the original JsonParser
   * @param ctxt the context of the deserialization operation.
   * @return the transformed object.
   * @throws IOException if an IO problem is encountered during transformation
   * @throws JsonProcessingException if the is a problem processing json during the transformation
   */
  protected abstract Object transform( I intermediate, ObjectMapper mapper, DeserializationContext ctxt ) throws IOException, JsonProcessingException;

  /**
   * Creates an ObjectMapper for the specified JsonParser, either by returning the codec on the JsonParser or creating a new
   * object mapper, if the codec is null or not an ObjectMapper instance.
   * 
   * @param jp the JsonParser that is being used to read the untransformed value.
   * @return an object mapper.
   */
  protected ObjectMapper objectMapper( JsonParser jp ) {
    ObjectCodec codec = jp.getCodec();
    if( codec == null )
      codec = new ObjectMapper();
    else if( !(codec instanceof ObjectMapper) )
      codec = new ObjectMapper(codec.getFactory());
    return (ObjectMapper) codec;
  }
}