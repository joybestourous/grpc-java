/*
 * Copyright 2015 The gRPC Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.grpc.netty;

import io.grpc.Channel;
import io.grpc.netty.ProtocolNegotiators.PlaintextProtocolNegotiator;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.ImmediateExecutor;
import io.netty.util.internal.ObjectUtil;

import java.util.concurrent.Executor;
import javax.annotation.Nullable;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.util.List;

/**
 * {@link CustomOptionalSslHandler} is a utility decoder to support both SSL and non-SSL handlers
 * based on the first message received.
 */
public class CustomOptionalSslHandler extends ByteToMessageDecoder {

  private final SslContext sslContext;
  private final Executor executor;
  private final ChannelHandler next;

  public CustomOptionalSslHandler(SslContext sslContext, ChannelHandler next, @Nullable Executor executor) {
    this.sslContext = ObjectUtil.checkNotNull(sslContext, "sslContext");
    this.next = ObjectUtil.checkNotNull(next, "next");
    if (executor != null) {
      this.executor = executor;
    } else {
      this.executor = ImmediateExecutor.INSTANCE;
    }
  }

  @Override
  protected void decode(ChannelHandlerContext context, ByteBuf in, List<Object> out) throws Exception {
    // SslUtils.SSL_RECORD_HEADER_LENGTH = 5
    if (in.readableBytes() < 5) {
      return;
    }
    if (SslHandler.isEncrypted(in)) {
      handleSsl(context);
    } else {
      handleNonSsl(context);
    }
  }

  private void handleSsl(ChannelHandlerContext context) {
    SslHandler sslHandler = null;
    try {
      sslHandler = newSslHandler(context, sslContext);
      context.pipeline().replace(this, newSslHandlerName(), sslHandler);
      sslHandler = null;
    } finally {
      // Since the SslHandler was not inserted into the pipeline the ownership of the SSLEngine was not
      // transferred to the SslHandler.
      if (sslHandler != null) {
        ReferenceCountUtil.safeRelease(sslHandler.engine());
      }
    }
  }

  private void handleNonSsl(ChannelHandlerContext context) {
    ChannelHandler handler = newNonSslHandler(context);
    if (handler != null) {
      context.pipeline().replace(this, newNonSslHandlerName(), handler);
    } else {
      context.pipeline().remove(this);
      context.pipeline().replace(ProtocolNegotiators.ServerOpportunisticTlsHandler.class, null, next);
      context.fireUserEventTriggered(ProtocolNegotiationEvent.DEFAULT);
    }
  }

  /**
   * Optionally specify the SSL handler name, this method may return {@code null}.
   * @return the name of the SSL handler.
   */
  protected String newSslHandlerName() {
    return null;
  }

  /**
   * Override to configure the SslHandler eg. {@link SSLParameters#setEndpointIdentificationAlgorithm(String)}.
   * The hostname and port is not known by this method so servers may want to override this method and use the
   * {@link SslContext#newHandler(ByteBufAllocator, String, int)} variant.
   *
   * @param context the {@link ChannelHandlerContext} to use.
   * @param sslContext the {@link SSLContext} to use.
   * @return the {@link SslHandler} which will replace the {@link CustomOptionalSslHandler} in the pipeline if the
   * traffic is SSL.
   */
  protected SslHandler newSslHandler(ChannelHandlerContext context, SslContext sslContext) {
    return sslContext.newHandler(context.alloc(), executor);
  }

  /**
   * Optionally specify the non-SSL handler name, this method may return {@code null}.
   * @return the name of the non-SSL handler.
   */
  protected String newNonSslHandlerName() {
    return null;
  }

  /**
   * Override to configure the ChannelHandler.
   * @param context the {@link ChannelHandlerContext} to use.
   * @return the {@link ChannelHandler} which will replace the {@link CustomOptionalSslHandler} in the pipeline
   * or {@code null} to simply remove the {@link CustomOptionalSslHandler} if the traffic is non-SSL.
   */
  protected ChannelHandler newNonSslHandler(ChannelHandlerContext context) {
    return null;
  }
}
