/*
 * Copyright 2025 The gRPC Authors
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

package io.grpc.datadog.rpcteam;

import io.grpc.Metadata;
import io.grpc.Status;
import java.util.concurrent.atomic.AtomicReference;
import javax.annotation.Nullable;

/**
 * Hooks for custom retry policies and throttling.
 *
 * <p>IT IS ONLY INTENDED FOR RPC TEAM USAGE. Do not use this class in your code.
 */
public final class ManagedRetryHooks {

  /** Pluggable per-channel retry throttling policy. Implementations must be concurrency-safe. */
  public interface RetryThrottler {
    /**
     * Returns true if the retry should be throttled (blocked). Called when the error meets
     * conditions for retrying and a throttling decision must be made.
     */
    boolean throttle();

    /**
     * Called at the start of every RPC attempt.
     *
     * @param isRetry true if this is a retry attempt, false for the first attempt.
     */
    void attemptStarted(boolean isRetry);

    /**
     * Called at the completion of every RPC attempt, regardless of success or failure.
     *
     * @param isRetry true if this was a retry attempt, false for the first attempt.
     */
    void attemptCompleted(boolean isRetry);
  }

  /** Decision from the custom retry hook. */
  public enum RetryDecision {
    /**
     * The hook did not have enough information to make a decision. The standard retry policy
     * (if any) will apply.
     */
    UNDECIDED,
    /** Retry the RPC using the associated custom retry policy. */
    RETRY,
    /** Do not retry the RPC. */
    NO_RETRY
  }

  /** Custom retry policy with backoff parameters, analogous to gRPC's RetryPolicy. */
  public static final class CustomRetryPolicy {
    public final int maxAttempts;
    public final long initialBackoffNanos;
    public final long maxBackoffNanos;
    public final double backoffMultiplier;

    public CustomRetryPolicy(
        int maxAttempts,
        long initialBackoffNanos,
        long maxBackoffNanos,
        double backoffMultiplier) {
      this.maxAttempts = maxAttempts;
      this.initialBackoffNanos = initialBackoffNanos;
      this.maxBackoffNanos = maxBackoffNanos;
      this.backoffMultiplier = backoffMultiplier;
    }
  }

  /** Hook called to determine whether an RPC should be retried. */
  public interface RetryHook {
    RetryDecision shouldRetry(Status status, Metadata trailers);
  }

  /** Factory for creating per-channel retry throttlers. */
  public interface RetryThrottlerFactory {
    RetryThrottler newThrottler(String target);
  }

  /** Handler for transforming error statuses before they are returned to the caller. */
  public interface ErrorHandler {
    Status handleError(Status status);
  }

  /**
   * The result of querying the custom retry hook.
   *
   * @see #queryCustomRetry(Status, Metadata)
   */
  public static final class HookResult {
    /** No hook registered, or hook returned {@link RetryDecision#UNDECIDED}. */
    public static final HookResult UNDECIDED = new HookResult(null, false);
    /** Hook returned {@link RetryDecision#NO_RETRY}. Standard retry policy is also suppressed. */
    public static final HookResult DENIED = new HookResult(null, true);

    /** Non-null when the hook returned {@link RetryDecision#RETRY}. */
    @Nullable public final CustomRetryPolicy retryPolicy;
    /** True when the hook explicitly denied the retry. */
    public final boolean denied;

    private HookResult(@Nullable CustomRetryPolicy retryPolicy, boolean denied) {
      this.retryPolicy = retryPolicy;
      this.denied = denied;
    }

    static HookResult retry(CustomRetryPolicy policy) {
      return new HookResult(policy, false);
    }
  }

  /** A no-op {@link RetryThrottler} that never throttles. */
  public static final RetryThrottler NOOP_THROTTLER = new RetryThrottler() {
    @Override
    public boolean throttle() {
      return false;
    }

    @Override
    public void attemptStarted(boolean isRetry) {}

    @Override
    public void attemptCompleted(boolean isRetry) {}
  };

  private static final AtomicReference<RetryHookWithPolicy> defaultRetryHook =
      new AtomicReference<RetryHookWithPolicy>();
  private static final AtomicReference<RetryThrottlerFactory> defaultRetryThrottlerFactory =
      new AtomicReference<RetryThrottlerFactory>();
  private static final AtomicReference<ErrorHandler> defaultErrorHandler =
      new AtomicReference<ErrorHandler>();

  private static final class RetryHookWithPolicy {
    final RetryHook hook;
    final CustomRetryPolicy policy;

    RetryHookWithPolicy(RetryHook hook, CustomRetryPolicy policy) {
      this.hook = hook;
      this.policy = policy;
    }
  }

  /**
   * Sets the custom retry hook and associated policy.
   *
   * <p>IT IS ONLY INTENDED FOR RPC TEAM USAGE. DO NOT USE THIS FUNCTION IN YOUR CODE.
   *
   * @throws IllegalArgumentException if the policy is invalid.
   */
  public static void adminOnlySetCustomRetryHook(
      @Nullable RetryHook hook, @Nullable CustomRetryPolicy policy) {
    if (hook == null) {
      defaultRetryHook.set(null);
      return;
    }
    validateCustomRetryPolicy(policy);
    defaultRetryHook.set(new RetryHookWithPolicy(hook, policy));
  }

  /**
   * Sets the factory used to create per-channel retry throttlers.
   *
   * <p>IT IS ONLY INTENDED FOR RPC TEAM USAGE. DO NOT USE THIS FUNCTION IN YOUR CODE.
   */
  public static void adminOnlySetCustomRetryThrottler(@Nullable RetryThrottlerFactory factory) {
    defaultRetryThrottlerFactory.set(factory);
  }

  /**
   * Sets the custom error handler.
   *
   * <p>IT IS ONLY INTENDED FOR RPC TEAM USAGE. DO NOT USE THIS FUNCTION IN YOUR CODE.
   */
  public static void adminOnlySetCustomErrorHandler(@Nullable ErrorHandler handler) {
    defaultErrorHandler.set(handler);
  }

  /**
   * Queries the custom retry hook for the given status and trailers.
   *
   * <ul>
   *   <li>Returns {@link HookResult#UNDECIDED} if no hook is registered or the hook returns
   *       {@link RetryDecision#UNDECIDED} — the standard retry policy (if any) applies.
   *   <li>Returns {@link HookResult#DENIED} if the hook returns {@link RetryDecision#NO_RETRY} —
   *       the RPC must not be retried, even if the standard retry policy would allow it.
   *   <li>Returns a {@link HookResult} with a non-null {@link HookResult#retryPolicy} if the hook
   *       returns {@link RetryDecision#RETRY}.
   * </ul>
   */
  public static HookResult queryCustomRetry(Status status, Metadata trailers) {
    RetryHookWithPolicy entry = defaultRetryHook.get();
    if (entry == null) {
      return HookResult.UNDECIDED;
    }
    RetryDecision decision = entry.hook.shouldRetry(status, trailers);
    if (decision == RetryDecision.RETRY) {
      return HookResult.retry(entry.policy);
    } else if (decision == RetryDecision.NO_RETRY) {
      return HookResult.DENIED;
    }
    return HookResult.UNDECIDED;
  }

  /**
   * Creates a new {@link RetryThrottler} for the given channel target using the custom factory,
   * or returns {@link #NOOP_THROTTLER} if no factory has been set.
   */
  public static RetryThrottler newRetryThrottler(String target) {
    RetryThrottlerFactory factory = defaultRetryThrottlerFactory.get();
    if (factory == null) {
      return NOOP_THROTTLER;
    }
    return factory.newThrottler(target);
  }

  /**
   * Applies the custom error handler to the status, returning the (possibly transformed) status.
   * Returns the original status if no handler is set or the status is {@code null}.
   */
  public static Status handleError(Status status) {
    ErrorHandler handler = defaultErrorHandler.get();
    if (handler == null || status == null) {
      return status;
    }
    return handler.handleError(status);
  }

  private static void validateCustomRetryPolicy(CustomRetryPolicy policy) {
    if (policy.maxAttempts <= 1) {
      throw new IllegalArgumentException("maxAttempts must be greater than 1");
    }
    if (policy.initialBackoffNanos <= 0) {
      throw new IllegalArgumentException("initialBackoffNanos must be greater than 0");
    }
    if (policy.maxBackoffNanos <= 0) {
      throw new IllegalArgumentException("maxBackoffNanos must be greater than 0");
    }
    if (policy.backoffMultiplier <= 0) {
      throw new IllegalArgumentException("backoffMultiplier must be greater than 0");
    }
  }

  private ManagedRetryHooks() {}
}
