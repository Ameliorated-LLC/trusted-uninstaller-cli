using System;
using System.ComponentModel.DataAnnotations;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using JetBrains.Annotations;
using Polly;
using Polly.Fallback;
using Polly.Retry;

namespace Core
{
    /// <summary>
    /// Class for wrapping code with resilience strategies such as retries, fallbacks, and timeouts.
    /// <br/><br/>This class also contains safe execution methods like <b>ExecuteSafe</b> to ignore exceptions in cases where the success of an operation is not critical. 
    /// </summary>
    /// <example><b>Wrap.Retry().Execute(() => </b><i>your code here...</i><b>)</b></example>
    public static class Wrap
    {
        #region Pipelines

        /// <summary>
        /// Retries operation.
        /// <br/>Will NOT retry upon an <b>OperationCanceledException</b>.
        /// </summary>
        /// <param name="attempts">Total number of attempts including the first call.</param>
        /// <param name="millisecondsDelay">Delay in milliseconds between attempts.</param>
        public static ResiliencePipeline Retry([Range(1, 1000)] int attempts = 3, int millisecondsDelay = 1500) => (attempts != 1
                ? new ResiliencePipelineBuilder()
                    .AddRetry(new RetryStrategyOptions()
                    {
                        // By default it retries on any exception except OperationCanceledException.
                        //ShouldHandle = arg => arg.Outcome.Exception != null ? PredicateResult.True() : PredicateResult.False(),
                        MaxRetryAttempts = attempts - 1,
                        Delay = TimeSpan.FromMilliseconds(millisecondsDelay),
                    })
                : new ResiliencePipelineBuilder()) // https://www.pollydocs.org/strategies/retry#defaults
            .Build();

        /// <summary>
        /// Retries operation.
        /// <br/>Will NOT retry upon an <b>OperationCanceledException</b>.
        /// </summary>
        /// <param name="timeout">Timeout for when to cancel the operation. This applies to each attempt individually, and will trigger a cancellation on the CancellationToken.</param>
        /// <param name="attempts">Total number of attempts including the first call.</param>
        /// <param name="millisecondsDelay">Delay in milliseconds between attempts.</param>
        public static ResiliencePipeline RetryWithTimeout(TimeSpan timeout, [Range(1, 1000)] int attempts = 3, int millisecondsDelay = 1500) => (attempts != 1
                ? new ResiliencePipelineBuilder()
                    .AddRetry(new RetryStrategyOptions()
                    {
                        // By default it retries on any exception except OperationCanceledException.
                        //ShouldHandle = arg => arg.Outcome.Exception != null ? PredicateResult.True() : PredicateResult.False(),
                        MaxRetryAttempts = attempts - 1,
                        Delay = TimeSpan.FromMilliseconds(millisecondsDelay),
                    })
                : new ResiliencePipelineBuilder()).AddTimeout(timeout)
            .Build();


        /// <summary>
        /// Retries extern client-helper.dll operation.
        /// <br/>If the function does NOT return "Success", it will register as a fail.
        /// </summary>
        /// <param name="attempts">Total number of attempts including the first call.</param>
        /// <param name="millisecondsDelay">Delay in milliseconds between attempts.</param>
        public static ResiliencePipeline<string> HelperRetry([Range(2, 1000)] int attempts = 3, int millisecondsDelay = 1500) => new ResiliencePipelineBuilder<string>()
            .AddFallback(new FallbackStrategyOptions<string>()
            {
                ShouldHandle = arg => arg.Outcome.Exception != null ? arg.Outcome.Exception.GetType() != typeof(OperationCanceledException) ? PredicateResult.True() : PredicateResult.False() : arg.Outcome.Result == "Success" ? PredicateResult.False() : PredicateResult.True(),
                FallbackAction = args =>
                {
                    // If this fallback code is reached, all retries failed.
                    // Since Polly does not throw an exception if the retry
                    // requirement (result == "Success") is not met, we force
                    // an exception here.
                    if (args.Outcome.Result != null)
                        throw new Exception(args.Outcome.Result);
                    else if (args.Outcome.Exception != null)
                        throw args.Outcome.Exception;

                    throw new Exception("HelperRetry fallback unexpected error.");
                }
            })
            .AddRetry(new RetryStrategyOptions<string>()
            {
                ShouldHandle = arg => arg.Outcome.Exception != null ? arg.Outcome.Exception.GetType() != typeof(OperationCanceledException) ? PredicateResult.True() : PredicateResult.False() : arg.Outcome.Result == "Success" ? PredicateResult.False() : PredicateResult.True(),
                MaxRetryAttempts = attempts - 1,
                Delay = TimeSpan.FromMilliseconds(millisecondsDelay),
            }) // https://www.pollydocs.org/strategies/retry#defaults
            .Build();

        /// <summary>
        /// Retries extern client-helper.dll operation.
        /// <br/>If the function does NOT return "Success", it will register as a fail.
        /// </summary>
        /// <param name="timeout">Timeout for when to cancel the operation. This applies to each attempt individually, and will trigger a cancellation on the CancellationToken.</param>
        /// <param name="attempts">Total number of attempts including the first call.</param>
        /// <param name="millisecondsDelay">Delay in milliseconds between attempts.</param>
        public static ResiliencePipeline<string> HelperRetryWithTimeout(TimeSpan timeout, [Range(2, 1000)] int attempts = 3, int millisecondsDelay = 1500) => new ResiliencePipelineBuilder<string>()
            .AddFallback(new FallbackStrategyOptions<string>()
            {
                ShouldHandle = arg => arg.Outcome.Exception != null ? arg.Outcome.Exception.GetType() != typeof(OperationCanceledException) ? PredicateResult.True() : PredicateResult.False() : arg.Outcome.Result == "Success" ? PredicateResult.False() : PredicateResult.True(),
                FallbackAction = args =>
                {
                    // If this fallback code is reached, all retries failed.
                    // Since Polly does not throw an exception if the retry
                    // requirement (result == "Success") is not met, we force
                    // an exception here.
                    if (args.Outcome.Result != null)
                        throw new Exception(args.Outcome.Result);
                    else if (args.Outcome.Exception != null)
                        throw args.Outcome.Exception;

                    throw new Exception("HelperRetry fallback unexpected error.");
                }
            })
            .AddRetry(new RetryStrategyOptions<string>()
            {
                ShouldHandle = arg => arg.Outcome.Exception != null ? arg.Outcome.Exception.GetType() != typeof(OperationCanceledException) ? PredicateResult.True() : PredicateResult.False() : arg.Outcome.Result == "Success" ? PredicateResult.False() : PredicateResult.True(),
                MaxRetryAttempts = attempts - 1,
                Delay = TimeSpan.FromMilliseconds(millisecondsDelay),
            }) // https://www.pollydocs.org/strategies/retry#defaults
            .Build();

        /// <summary>
        /// Retries extern Win32 operation.
        /// <br/>If the function does NOT return 0, it will register as a fail.
        /// </summary>
        /// <param name="attempts">Total number of attempts including the first call.</param>
        /// <param name="millisecondsDelay">Delay in milliseconds between attempts.</param>
        public static ResiliencePipeline<int> Win32IntegerRetry([Range(2, 1000)] int attempts = 3, int millisecondsDelay = 1500) => new ResiliencePipelineBuilder<int>()
            .AddRetry(new RetryStrategyOptions<int>()
            {
                ShouldHandle = arg => arg.Outcome.Exception != null ? arg.Outcome.Exception.GetType() != typeof(OperationCanceledException) ? PredicateResult.True() : PredicateResult.False() : arg.Outcome.Result == 0 ? PredicateResult.False() : PredicateResult.True(),
                MaxRetryAttempts = attempts - 1,
                Delay = TimeSpan.FromMilliseconds(millisecondsDelay),
            })
            .Build();

        /// <summary>
        /// Retries extern Win32 operation.
        /// <br/>If the function does NOT return 0, it will register as a fail.
        /// </summary>
        /// <param name="timeout">Timeout for when to cancel the operation. This applies to each attempt individually, and will trigger a cancellation on the CancellationToken.</param>
        /// <param name="attempts">Total number of attempts including the first call.</param>
        /// <param name="millisecondsDelay">Delay in milliseconds between attempts.</param>
        public static ResiliencePipeline<int> Win32IntegerRetryWithTimeout(TimeSpan timeout, [Range(2, 1000)] int attempts = 3, int millisecondsDelay = 1500) => new ResiliencePipelineBuilder<int>()
            .AddRetry(new RetryStrategyOptions<int>()
            {
                ShouldHandle = arg => arg.Outcome.Exception != null ? arg.Outcome.Exception.GetType() != typeof(OperationCanceledException) ? PredicateResult.True() : PredicateResult.False() : arg.Outcome.Result == 0 ? PredicateResult.False() : PredicateResult.True(),
                MaxRetryAttempts = attempts - 1,
                Delay = TimeSpan.FromMilliseconds(millisecondsDelay),
            })
            .AddTimeout(timeout).Build();

        /// <summary>
        /// Retries extern Win32 operation.
        /// <br/>If the function does NOT return true, it will register as a fail.
        /// </summary>
        /// <param name="attempts">Total number of attempts including the first call.</param>
        /// <param name="millisecondsDelay">Delay in milliseconds between attempts.</param>
        public static ResiliencePipeline<bool> Win32BoolRetry([Range(2, 1000)] int attempts = 3, int millisecondsDelay = 1500) => new ResiliencePipelineBuilder<bool>()
            .AddRetry(new RetryStrategyOptions<bool>()
            {
                ShouldHandle = arg => arg.Outcome.Exception != null ? arg.Outcome.Exception.GetType() != typeof(OperationCanceledException) ? PredicateResult.True() : PredicateResult.False() : arg.Outcome.Result ? PredicateResult.False() : PredicateResult.True(),
                MaxRetryAttempts = attempts - 1,
                Delay = TimeSpan.FromMilliseconds(millisecondsDelay),
            })
            .Build();

        /// <summary>
        /// Retries extern Win32 operation.
        /// <br/>If the function does NOT return true, it will register as a fail.
        /// </summary>
        /// <param name="timeout">Timeout for when to cancel the operation. This applies to each attempt individually, and will trigger a cancellation on the CancellationToken.</param>
        /// <param name="attempts">Total number of attempts including the first call.</param>
        /// <param name="millisecondsDelay">Delay in milliseconds between attempts.</param>
        public static ResiliencePipeline<bool> Win32BoolRetryWithTimeout(TimeSpan timeout, [Range(2, 1000)] int attempts = 3, int millisecondsDelay = 1500) => new ResiliencePipelineBuilder<bool>()
            .AddRetry(new RetryStrategyOptions<bool>()
            {
                ShouldHandle = arg => arg.Outcome.Exception != null ? arg.Outcome.Exception.GetType() != typeof(OperationCanceledException) ? PredicateResult.True() : PredicateResult.False() : arg.Outcome.Result ? PredicateResult.False() : PredicateResult.True(),
                MaxRetryAttempts = attempts - 1,
                Delay = TimeSpan.FromMilliseconds(millisecondsDelay),
            })
            .AddTimeout(timeout).Build();

                /// <summary>
        /// Retries extern Win32 operation.
        /// <br/>If the function returns INVALID_HANDLE_VALUE, it will register as a fail.
        /// </summary>
        /// <param name="attempts">Total number of attempts including the first call.</param>
        /// <param name="millisecondsDelay">Delay in milliseconds between attempts.</param>
        public static ResiliencePipeline<SafeHandle> Win32HandleRetry(int attempts = 3, int millisecondsDelay = 1500) => new ResiliencePipelineBuilder<SafeHandle>()
            .AddRetry(new RetryStrategyOptions<SafeHandle>()
            {
                ShouldHandle = arg => arg.Outcome.Exception != null ? arg.Outcome.Exception.GetType() != typeof(OperationCanceledException) ? PredicateResult.True() : PredicateResult.False() : arg.Outcome.Result == null || arg.Outcome.Result.DangerousGetHandle() != Win32.INVALID_HANDLE_VALUE ? PredicateResult.False() : PredicateResult.True(),
                MaxRetryAttempts = attempts - 1,
                Delay = TimeSpan.FromMilliseconds(millisecondsDelay),
            })
            .Build();

        /// <summary>
        /// Retries extern Win32 operation.
        /// <br/>If the function returns INVALID_HANDLE_VALUE, it will register as a fail.
        /// </summary>
        /// <param name="timeout">Timeout for when to cancel the operation. This applies to each attempt individually, and will trigger a cancellation on the CancellationToken.</param>
        /// <param name="attempts">Total number of attempts including the first call.</param>
        /// <param name="millisecondsDelay">Delay in milliseconds between attempts.</param>
        public static ResiliencePipeline<SafeHandle> Win32HandleRetryWithTimeout(TimeSpan timeout, int attempts = 3, int millisecondsDelay = 1500) => new ResiliencePipelineBuilder<SafeHandle>()
            .AddRetry(new RetryStrategyOptions<SafeHandle>()
            {
                ShouldHandle = arg => arg.Outcome.Exception != null ? arg.Outcome.Exception.GetType() != typeof(OperationCanceledException) ? PredicateResult.True() : PredicateResult.False() : arg.Outcome.Result == null || arg.Outcome.Result.DangerousGetHandle() != Win32.INVALID_HANDLE_VALUE ? PredicateResult.False() : PredicateResult.True(),
                MaxRetryAttempts = attempts - 1,
                Delay = TimeSpan.FromMilliseconds(millisecondsDelay),
            })
            .AddTimeout(timeout).Build();
        
        #endregion

        #region Return Structs

        // Safe return value struct
        public struct SafeResult<TResult>
        {
            [CanBeNull] public TResult Value;
            [CanBeNull] public Exception Exception;
            public bool Failed => Exception != null;

            public SafeResult(TResult result, Exception exception)
            {
                Value = result;
                Exception = exception;
            }

            internal SafeResult(SafeResult<TResult, object> result)
            {
                Value = result.Value;
                Exception = result.Exception;
            }
        }

        // Safe return value struct without Result CanBeNull
        public struct SafeResult<TResult, T>
        {
            public TResult Value;
            [CanBeNull] public Exception Exception;
            public bool Failed() => Exception != null;

            public SafeResult(TResult result, Exception exception)
            {
                Value = result;
                Exception = exception;
            }
        }

        // Safe return value struct
        public struct SafeFallbackResult<TResult>
        {
            [CanBeNull] public TResult Value;
            [CanBeNull] public Exception Exception;
            [CanBeNull] public Exception FallbackException;
            public bool FallbackTriggered => Exception != null;
            public bool Failed => FallbackException != null;

            public SafeFallbackResult(TResult result, Exception exception, Exception fallbackException)
            {
                Value = result;
                Exception = exception;
                FallbackException = fallbackException;
            }

            internal SafeFallbackResult(SafeFallbackResult<TResult, object> result)
            {
                Value = result.Value;
                Exception = result.Exception;
                FallbackException = result.FallbackException;
            }
        }

        // Safe return value struct without Result CanBeNull
        public struct SafeFallbackResult<TResult, T>
        {
            public TResult Value;
            [CanBeNull] public Exception Exception;
            [CanBeNull] public Exception FallbackException;
            public bool FallbackTriggered => Exception != null;
            public bool Failed => FallbackException != null;

            public SafeFallbackResult(TResult result, Exception exception, Exception fallbackException)
            {
                Value = result;
                Exception = exception;
                FallbackException = fallbackException;
            }
        }

        public class DoubleException : Exception
        {
            [NotNull] public Exception PrimaryException;
            [CanBeNull] public Exception FallbackException;
            public bool FallbackTriggered => true;
            public bool Failed => FallbackException != null;

            public DoubleException(Exception primaryException, Exception fallbackException)
            {
                PrimaryException = primaryException;
                FallbackException = fallbackException;
            }
        }

        public class DoubleException<T> : Exception
        {
            [NotNull] public Exception PrimaryException;
            [NotNull] public Exception FallbackException;
            public bool FallbackTriggered => true;
            public bool Failed => true;

            public DoubleException(Exception primaryException, Exception fallbackException)
            {
                PrimaryException = primaryException;
                FallbackException = fallbackException;
            }
        }

        #endregion

        #region Execution Methods

        #region Safe

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the result type.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        [NotNull]
        public static SafeResult<TResult> ExecuteSafe<TResult>(this ResiliencePipeline<TResult> pipeline, [NotNull] Func<TResult> operation, bool logExceptions = false, Log.LogOptions logOptions = null) => new SafeResult<TResult>(ExecuteSafe(pipeline, operation, default!, logExceptions, logOptions));

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the value specified by <b>errorResultValue</b>.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        [NotNull]
        public static SafeResult<TResult, object> ExecuteSafe<TResult>(this ResiliencePipeline<TResult> pipeline, [NotNull] Func<TResult> operation, [NotNull] TResult errorResultValue, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            try
            {
                return new SafeResult<TResult, object>(pipeline.Execute(operation), null);
            }
            catch (Exception e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(e, logOptions);
                return new SafeResult<TResult, object>(errorResultValue, e);
            }
        }

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the result type.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        [NotNull]
        public static SafeResult<TResult> ExecuteSafe<TResult>(this ResiliencePipeline pipeline, [NotNull] Func<TResult> operation, bool logExceptions = false, Log.LogOptions logOptions = null) => new SafeResult<TResult>(ExecuteSafe(pipeline, operation, default!, logExceptions, logOptions));

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the value specified by <b>errorResultValue</b>.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        [NotNull]
        public static SafeResult<TResult, object> ExecuteSafe<TResult>(this ResiliencePipeline pipeline, [NotNull] Func<TResult> operation, [NotNull] TResult errorResultValue, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            try
            {
                return new SafeResult<TResult, object>(pipeline.Execute(operation), null);
            }
            catch (Exception e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(e, logOptions);
                return new SafeResult<TResult, object>(errorResultValue, e);
            }
        }

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>The exception thrown, or null if successful.</returns>
        [CanBeNull]
        public static Exception ExecuteSafe(this ResiliencePipeline pipeline, [NotNull] Action operation, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            try
            {
                pipeline.Execute(operation);
            }
            catch (Exception e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(e, logOptions);
                return e;
            }

            return null;
        }

        /// <summary>
        /// Invokes <b>operation</b> safely, similar to <b>try { operation.Invoke() } catch { }</b>.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the result type.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        [NotNull]
        public static SafeResult<TResult> ExecuteSafe<TResult>([NotNull] Func<TResult> operation, bool logExceptions = false, Log.LogOptions logOptions = null) => new SafeResult<TResult>(ExecuteSafe(operation, default!, logExceptions, logOptions));

        /// <summary>
        /// Invokes <b>operation</b> safely, similar to <b>try { operation.Invoke() } catch { }</b>.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the value specified by <b>errorResultValue</b>.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        [NotNull]
        public static SafeResult<TResult, object> ExecuteSafe<TResult>([NotNull] Func<TResult> operation, [NotNull] TResult errorResultValue, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            try
            {
                return new SafeResult<TResult, object>(operation.Invoke(), null);
            }
            catch (Exception e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(e, logOptions);
                return new SafeResult<TResult, object>(errorResultValue, e);
            }
        }

        /// <summary>
        /// Invokes <b>operation</b> safely, similar to <b>try { operation.Invoke() } catch { }</b>.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns <b>null</b> upon success, otherwise the exception thrown.</returns>
        [CanBeNull]
        public static Exception ExecuteSafe([NotNull] Action operation, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            try
            {
                operation.Invoke();
            }
            catch (Exception e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(e, logOptions);
                return e;
            }

            return null;
        }

        #endregion

        #region Fallback Safe

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely. If that fails, this executes <b>pipeline.Execute(fallback)</b> safely, or <b>fallback.Invoke()</b> if <b>usePipelineForFallback</b> is specified.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="usePipelineForFallback">Specifies to run <b>fallback</b> without the supplied pipeline.</param>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the return type.<br/><b>PrimaryException</b>: Set to null if <b>operation</b> was successful, otherwise the exception from the operation.<br/><b>FallbackException</b>: Set to null if the <b>fallback</b> was successful or was not called, otherwise the exception from the fallback.</returns>
        /// <example><b>await pipeline.ExecuteWithFallbackSafe(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        [NotNull]
        public static SafeFallbackResult<TResult> ExecuteWithFallbackSafe<TResult>(this ResiliencePipeline<TResult> pipeline, [NotNull] Func<TResult> operation, [NotNull] Func<TResult> fallback, bool logExceptions = false, Log.LogOptions logOptions = null, bool usePipelineForFallback = true) => new SafeFallbackResult<TResult>(ExecuteWithFallbackSafe(pipeline, operation, fallback, default!, logExceptions, logOptions, usePipelineForFallback));

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely. If that fails, this executes <b>pipeline.Execute(fallback)</b> safely, or <b>fallback.Invoke()</b> if <b>usePipelineForFallback</b> is specified.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="usePipelineForFallback">Specifies to run <b>fallback</b> without the supplied pipeline.</param>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the value specified by <b>errorResultValue</b>.<br/><b>PrimaryException</b>: Set to null if <b>operation</b> was successful, otherwise the exception from the operation.<br/><b>FallbackException</b>: Set to null if the <b>fallback</b> was successful or was not called, otherwise the exception from the fallback.</returns>
        /// <example><b>await pipeline.ExecuteWithFallbackSafe(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>, "Error")</b></example>
        [NotNull]
        public static SafeFallbackResult<TResult, object> ExecuteWithFallbackSafe<TResult>(this ResiliencePipeline<TResult> pipeline, [NotNull] Func<TResult> operation, [NotNull] Func<TResult> fallback, [NotNull] TResult errorResultValue, bool logExceptions = false, Log.LogOptions logOptions = null, bool usePipelineForFallback = true)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));
            try
            {
                return new SafeFallbackResult<TResult, object>(pipeline.Execute(operation), null, null);
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                
                try
                {
                    if (usePipelineForFallback)
                        return new SafeFallbackResult<TResult, object>(pipeline.Execute(fallback), primaryException, null);
                    else
                        return new SafeFallbackResult<TResult, object>(fallback.Invoke(), primaryException, null);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    return new SafeFallbackResult<TResult, object>(errorResultValue, primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely. If that fails, this executes <b>pipeline.Execute(fallback)</b> safely, or <b>fallback.Invoke()</b> if <b>usePipelineForFallback</b> is specified.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="usePipelineForFallback">Specifies to run <b>fallback</b> without the supplied pipeline.</param>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the return type.<br/><b>PrimaryException</b>: Set to null if <b>operation</b> was successful, otherwise the exception from the operation.<br/><b>FallbackException</b>: Set to null if the <b>fallback</b> was successful or was not called, otherwise the exception from the fallback.</returns>
        /// <example><b>await pipeline.ExecuteWithFallbackSafe(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        [NotNull]
        public static SafeFallbackResult<TResult> ExecuteWithFallbackSafe<TResult>(this ResiliencePipeline pipeline, [NotNull] Func<TResult> operation, [NotNull] Func<TResult> fallback, bool logExceptions = false, Log.LogOptions logOptions = null, bool usePipelineForFallback = true) => new SafeFallbackResult<TResult>(ExecuteWithFallbackSafe(pipeline, operation, fallback, default!, logExceptions, logOptions, usePipelineForFallback));

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely. If that fails, this executes <b>pipeline.Execute(fallback)</b> safely, or <b>fallback.Invoke()</b> if <b>usePipelineForFallback</b> is specified.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="usePipelineForFallback">Specifies to run <b>fallback</b> without the supplied pipeline.</param>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the value specified by <b>errorResultValue</b>.<br/><b>PrimaryException</b>: Set to null if <b>operation</b> was successful, otherwise the exception from the operation.<br/><b>FallbackException</b>: Set to null if the <b>fallback</b> was successful or was not called, otherwise the exception from the fallback.</returns>
        /// <example><b>await pipeline.ExecuteWithFallbackSafe(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>, "Error")</b></example>
        [NotNull]
        public static SafeFallbackResult<TResult, object> ExecuteWithFallbackSafe<TResult>(this ResiliencePipeline pipeline, [NotNull] Func<TResult> operation, [NotNull] Func<TResult> fallback, [NotNull] TResult errorResultValue, bool logExceptions = false, Log.LogOptions logOptions = null, bool usePipelineForFallback = true)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));
            try
            {
                return new SafeFallbackResult<TResult, object>(pipeline.Execute(operation), null, null);
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                
                try
                {
                    if (usePipelineForFallback)
                        return new SafeFallbackResult<TResult, object>(pipeline.Execute(fallback), primaryException, null);
                    else
                        return new SafeFallbackResult<TResult, object>(fallback.Invoke(), primaryException, null);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    return new SafeFallbackResult<TResult, object>(errorResultValue, primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely. If that fails, this executes <b>pipeline.Execute(fallback)</b> safely, or <b>fallback.Invoke()</b> if <b>usePipelineForFallback</b> is specified.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="usePipelineForFallback">Specifies to run <b>fallback</b> without the supplied pipeline.</param>
        /// <returns>Returns a <b>DoubleException</b>:<br/><b>PrimaryException</b>: Set to null if <b>operation</b> was successful, otherwise the exception from the operation.<br/><b>FallbackException</b>: Set to null if the <b>fallback</b> was successful or was not called, otherwise the exception from the fallback.</returns>
        /// <example><b>await pipeline.ExecuteWithFallbackSafe(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        [CanBeNull]
        public static DoubleException ExecuteWithFallbackSafe(this ResiliencePipeline pipeline, [NotNull] Action operation, [NotNull] Action fallback, bool logExceptions = false, Log.LogOptions logOptions = null, bool usePipelineForFallback = true)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));
            try
            {
                pipeline.Execute(operation);
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                try
                {
                    if (usePipelineForFallback)
                        pipeline.Execute(fallback);
                    else
                        fallback.Invoke();
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    return new DoubleException(primaryException, fallbackException);
                }

                return new DoubleException(primaryException, null);
            }

            return null;
        }

        /// <summary>
        /// Invokes <b>operation</b> safely, effectively <b>try { operation.Invoke() } catch { }</b>. If that fails, the same is attempted with <b>fallback</b>.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the result type.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        /// <example><b>await ExecuteWithFallbackSafe(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        [NotNull]
        public static SafeFallbackResult<TResult> ExecuteWithFallbackSafe<TResult>([NotNull] Func<TResult> operation, [NotNull] Func<TResult> fallback, bool logExceptions = false, Log.LogOptions logOptions = null) => new SafeFallbackResult<TResult>(ExecuteWithFallbackSafe(operation, fallback, default!, logExceptions, logOptions));

        /// <summary>
        /// Invokes <b>operation</b> safely, similar to <b>try { operation.Invoke() } catch { }</b>. If that fails, the same is attempted with <b>fallback</b>.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the value specified by <b>errorResultValue</b>.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        /// <example><b>await ExecuteWithFallbackSafe(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>, "Error")</b></example>
        [NotNull]
        public static SafeFallbackResult<TResult, object> ExecuteWithFallbackSafe<TResult>([NotNull] Func<TResult> operation, [NotNull] Func<TResult> fallback, [NotNull] TResult errorResultValue, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));
            try
            {
                return new SafeFallbackResult<TResult, object>(operation.Invoke(), null, null);
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                try
                {
                    return new SafeFallbackResult<TResult, object>(fallback.Invoke(), primaryException, null);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    return new SafeFallbackResult<TResult, object>(errorResultValue, primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Invokes <b>operation</b> safely, similar to <b>try { operation.Invoke() } catch { }</b>.<br/><br/>
        /// DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns <b>null</b> if the fallback was not needed, otherwise a <b>DoubleException</b> with the <b>fallback</b> and/or <b>operation</b> exception.</returns>
        /// <example><b>await ExecuteWithFallbackSafe(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        [CanBeNull]
        public static DoubleException ExecuteWithFallbackSafe([NotNull] Action operation, [NotNull] Action fallback, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));
            try
            {
                operation.Invoke();
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                try
                {
                    fallback.Invoke();
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    return new DoubleException(primaryException, fallbackException);
                }

                return new DoubleException(primaryException, null);
            }

            return null;
        }

        #endregion

        #region Fallback Unsafe

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b>. If that fails, this executes <b>pipeline.Execute(fallback)</b>, or <b>fallback.Invoke()</b> if <b>usePipelineForFallback</b> is specified.
        /// </summary>
        /// <exception cref="DoubleException">This will always be the exception thrown if both <b>operation</b> and <b>fallback</b> fail, and contains the corresponding exceptions.</exception>
        /// <example><b>await pipeline.ExecuteWithFallback(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        public static TResult ExecuteWithFallback<TResult>(this ResiliencePipeline<TResult> pipeline, [NotNull] Func<TResult> operation, [NotNull] Func<TResult> fallback, bool logExceptions = false, Log.LogOptions logOptions = null, bool usePipelineForFallback = true)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));

            try
            {
                return pipeline.Execute(operation);
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                try
                {
                    if (usePipelineForFallback)
                        return pipeline.Execute(fallback);
                    else
                        return fallback.Invoke();
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    throw new DoubleException(primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b>. If that fails, this executes <b>pipeline.Execute(fallback)</b>, or <b>fallback.Invoke()</b> if <b>usePipelineForFallback</b> is specified.
        /// </summary>
        /// <exception cref="DoubleException">This will always be the exception thrown if both <b>operation</b> and <b>fallback</b> fail, and contains the corresponding exceptions.</exception>
        /// <example><b>await pipeline.ExecuteWithFallback(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        public static TResult ExecuteWithFallback<TResult>(this ResiliencePipeline pipeline, [NotNull] Func<TResult> operation, [NotNull] Func<TResult> fallback, bool logExceptions = false, Log.LogOptions logOptions = null, bool usePipelineForFallback = true)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));

            try
            {
                return pipeline.Execute(operation);
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                try
                {
                    if (usePipelineForFallback)
                        return pipeline.Execute(fallback);
                    else
                        return fallback.Invoke();
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    throw new DoubleException(primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b>. If that fails, this executes <b>pipeline.Execute(fallback)</b>, or <b>fallback.Invoke()</b> if <b>usePipelineForFallback</b> is specified.
        /// </summary>
        /// <exception cref="DoubleException">This will always be the exception thrown if both <b>operation</b> and <b>fallback</b> fail, and contains the corresponding exceptions.</exception>
        /// <example><b>await pipeline.ExecuteWithFallback(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        public static void ExecuteWithFallback(this ResiliencePipeline pipeline, [NotNull] Action operation, [NotNull] Action fallback, bool logExceptions = false, Log.LogOptions logOptions = null, bool usePipelineForFallback = true)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));

            try
            {
                pipeline.Execute(operation);
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, "Fallback: " + primaryException.Message, logOptions);
                try
                {
                    if (usePipelineForFallback)
                        pipeline.Execute(fallback);
                    else
                        fallback.Invoke();
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    throw new DoubleException(primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Invokes <b>operation</b>. If that fails, this invokes <b>fallback</b>.
        /// </summary>
        /// <exception cref="DoubleException">This will always be the exception thrown if both <b>operation</b> and <b>fallback</b> fail, and contains the corresponding exceptions.</exception>
        /// <example><b>await ExecuteWithFallback(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        [NotNull]
        public static TResult ExecuteWithFallback<TResult>([NotNull] Func<TResult> operation, [NotNull] Func<TResult> fallback, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));

            try
            {
                return operation.Invoke();
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                try
                {
                    return fallback.Invoke();
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    throw new DoubleException(primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Invokes <b>operation</b>. If that fails, this invokes <b>fallback</b>.
        /// </summary>
        /// <exception cref="DoubleException">This will always be the exception thrown if both <b>operation</b> and <b>fallback</b> fail, and contains the corresponding exceptions.</exception>
        /// <example><b>await ExecuteWithFallback(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        public static void ExecuteWithFallback([NotNull] Action operation, [NotNull] Action fallback, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));

            try
            {
                operation.Invoke();
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                try
                {
                    fallback.Invoke();
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    throw new DoubleException(primaryException, fallbackException);
                }
            }
        }

        #endregion
        
        #region CancellationToken
        
        #region Safe

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the result type.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        [NotNull]
        public static SafeResult<TResult> ExecuteSafe<TResult>(this ResiliencePipeline<TResult> pipeline, [NotNull] Func<CancellationToken, TResult> operation, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null) => new SafeResult<TResult>(ExecuteSafe(pipeline, operation, default!, cancellationToken, logExceptions, logOptions));

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the value specified by <b>errorResultValue</b>.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        [NotNull]
        public static SafeResult<TResult, object> ExecuteSafe<TResult>(this ResiliencePipeline<TResult> pipeline, [NotNull] Func<CancellationToken, TResult> operation, [NotNull] TResult errorResultValue, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return new SafeResult<TResult, object>(pipeline.Execute(operation, cancellationToken), null);
            }
            catch (Exception e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(e, logOptions);
                return new SafeResult<TResult, object>(errorResultValue, e);
            }
        }

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the result type.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        [NotNull]
        public static SafeResult<TResult> ExecuteSafe<TResult>(this ResiliencePipeline pipeline, [NotNull] Func<CancellationToken, TResult> operation, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null) => new SafeResult<TResult>(ExecuteSafe(pipeline, operation, default!, cancellationToken, logExceptions, logOptions));

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the value specified by <b>errorResultValue</b>.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        [NotNull]
        public static SafeResult<TResult, object> ExecuteSafe<TResult>(this ResiliencePipeline pipeline, [NotNull] Func<CancellationToken, TResult> operation, [NotNull] TResult errorResultValue, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return new SafeResult<TResult, object>(pipeline.Execute(operation, cancellationToken), null);
            }
            catch (Exception e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(e, logOptions);
                return new SafeResult<TResult, object>(errorResultValue, e);
            }
        }

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>The exception thrown, or null if successful.</returns>
        [CanBeNull]
        public static Exception ExecuteSafe(this ResiliencePipeline pipeline, [NotNull] Action<CancellationToken> operation, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                pipeline.Execute(operation, cancellationToken);
            }
            catch (Exception e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(e, logOptions);
                return e;
            }

            return null;
        }

        /// <summary>
        /// Invokes <b>operation</b> safely, similar to <b>try { operation.Invoke() } catch { }</b>.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the result type.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        [NotNull]
        public static SafeResult<TResult> ExecuteSafe<TResult>([NotNull] Func<CancellationToken, TResult> operation, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null) => new SafeResult<TResult>(ExecuteSafe(operation, default!, cancellationToken, logExceptions, logOptions));

        /// <summary>
        /// Invokes <b>operation</b> safely, similar to <b>try { operation.Invoke() } catch { }</b>.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the value specified by <b>errorResultValue</b>.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        [NotNull]
        public static SafeResult<TResult, object> ExecuteSafe<TResult>([NotNull] Func<CancellationToken, TResult> operation, [NotNull] TResult errorResultValue, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return new SafeResult<TResult, object>(operation.Invoke(cancellationToken), null);
            }
            catch (Exception e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(e, logOptions);
                return new SafeResult<TResult, object>(errorResultValue, e);
            }
        }

        /// <summary>
        /// Invokes <b>operation</b> safely, similar to <b>try { operation.Invoke() } catch { }</b>.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns <b>null</b> upon success, otherwise the exception thrown.</returns>
        [CanBeNull]
        public static Exception ExecuteSafe([NotNull] Action<CancellationToken> operation, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                operation.Invoke(cancellationToken);
            }
            catch (Exception e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(e, logOptions);
                return e;
            }

            return null;
        }

        #endregion

        #region Fallback Safe

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely. If that fails, this executes <b>pipeline.Execute(fallback)</b> safely, or <b>fallback.Invoke()</b> if <b>usePipelineForFallback</b> is specified.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="usePipelineForFallback">Specifies to run <b>fallback</b> without the supplied pipeline.</param>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the return type.<br/><b>PrimaryException</b>: Set to null if <b>operation</b> was successful, otherwise the exception from the operation.<br/><b>FallbackException</b>: Set to null if the <b>fallback</b> was successful or was not called, otherwise the exception from the fallback.</returns>
        /// <example><b>await pipeline.ExecuteWithFallbackSafe(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        [NotNull]
        public static SafeFallbackResult<TResult> ExecuteWithFallbackSafe<TResult>(this ResiliencePipeline<TResult> pipeline, [NotNull] Func<CancellationToken, TResult> operation, [NotNull] Func<CancellationToken, TResult> fallback, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null, bool usePipelineForFallback = true) => new SafeFallbackResult<TResult>(ExecuteWithFallbackSafe(pipeline, operation, fallback, default!, cancellationToken, logExceptions, logOptions, usePipelineForFallback));

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely. If that fails, this executes <b>pipeline.Execute(fallback)</b> safely, or <b>fallback.Invoke()</b> if <b>usePipelineForFallback</b> is specified.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="usePipelineForFallback">Specifies to run <b>fallback</b> without the supplied pipeline.</param>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the value specified by <b>errorResultValue</b>.<br/><b>PrimaryException</b>: Set to null if <b>operation</b> was successful, otherwise the exception from the operation.<br/><b>FallbackException</b>: Set to null if the <b>fallback</b> was successful or was not called, otherwise the exception from the fallback.</returns>
        /// <example><b>await pipeline.ExecuteWithFallbackSafe(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>, "Error")</b></example>
        [NotNull]
        public static SafeFallbackResult<TResult, object> ExecuteWithFallbackSafe<TResult>(this ResiliencePipeline<TResult> pipeline, [NotNull] Func<CancellationToken, TResult> operation, [NotNull] Func<CancellationToken, TResult> fallback, [NotNull] TResult errorResultValue, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null, bool usePipelineForFallback = true)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return new SafeFallbackResult<TResult, object>(pipeline.Execute(operation, cancellationToken), null, null);
            }
            catch (Exception primaryException)
            {
                if (logExceptions && !(primaryException is OperationCanceledException))
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    if (usePipelineForFallback)
                        return new SafeFallbackResult<TResult, object>(pipeline.Execute(fallback, cancellationToken), primaryException, null);
                    else
                        return new SafeFallbackResult<TResult, object>(fallback.Invoke(cancellationToken), primaryException, null);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    return new SafeFallbackResult<TResult, object>(errorResultValue, primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely. If that fails, this executes <b>pipeline.Execute(fallback)</b> safely, or <b>fallback.Invoke()</b> if <b>usePipelineForFallback</b> is specified.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="usePipelineForFallback">Specifies to run <b>fallback</b> without the supplied pipeline.</param>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the return type.<br/><b>PrimaryException</b>: Set to null if <b>operation</b> was successful, otherwise the exception from the operation.<br/><b>FallbackException</b>: Set to null if the <b>fallback</b> was successful or was not called, otherwise the exception from the fallback.</returns>
        /// <example><b>await pipeline.ExecuteWithFallbackSafe(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        [NotNull]
        public static SafeFallbackResult<TResult> ExecuteWithFallbackSafe<TResult>(this ResiliencePipeline pipeline, [NotNull] Func<CancellationToken, TResult> operation, [NotNull] Func<CancellationToken, TResult> fallback, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null, bool usePipelineForFallback = true) => new SafeFallbackResult<TResult>(ExecuteWithFallbackSafe(pipeline, operation, fallback, default!, cancellationToken, logExceptions, logOptions, usePipelineForFallback));

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely. If that fails, this executes <b>pipeline.Execute(fallback)</b> safely, or <b>fallback.Invoke()</b> if <b>usePipelineForFallback</b> is specified.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="usePipelineForFallback">Specifies to run <b>fallback</b> without the supplied pipeline.</param>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the value specified by <b>errorResultValue</b>.<br/><b>PrimaryException</b>: Set to null if <b>operation</b> was successful, otherwise the exception from the operation.<br/><b>FallbackException</b>: Set to null if the <b>fallback</b> was successful or was not called, otherwise the exception from the fallback.</returns>
        /// <example><b>await pipeline.ExecuteWithFallbackSafe(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>, "Error")</b></example>
        [NotNull]
        public static SafeFallbackResult<TResult, object> ExecuteWithFallbackSafe<TResult>(this ResiliencePipeline pipeline, [NotNull] Func<CancellationToken, TResult> operation, [NotNull] Func<CancellationToken, TResult> fallback, [NotNull] TResult errorResultValue, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null, bool usePipelineForFallback = true)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return new SafeFallbackResult<TResult, object>(pipeline.Execute(operation, cancellationToken), null, null);
            }
            catch (Exception primaryException)
            {
                if (logExceptions && !(primaryException is OperationCanceledException))
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    if (usePipelineForFallback)
                        return new SafeFallbackResult<TResult, object>(pipeline.Execute(fallback, cancellationToken), primaryException, null);
                    else
                        return new SafeFallbackResult<TResult, object>(fallback.Invoke(cancellationToken), primaryException, null);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    return new SafeFallbackResult<TResult, object>(errorResultValue, primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b> safely. If that fails, this executes <b>pipeline.Execute(fallback)</b> safely, or <b>fallback.Invoke()</b> if <b>usePipelineForFallback</b> is specified.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="usePipelineForFallback">Specifies to run <b>fallback</b> without the supplied pipeline.</param>
        /// <returns>Returns a <b>DoubleException</b>:<br/><b>PrimaryException</b>: Set to null if <b>operation</b> was successful, otherwise the exception from the operation.<br/><b>FallbackException</b>: Set to null if the <b>fallback</b> was successful or was not called, otherwise the exception from the fallback.</returns>
        /// <example><b>await pipeline.ExecuteWithFallbackSafe(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        [CanBeNull]
        public static DoubleException ExecuteWithFallbackSafe(this ResiliencePipeline pipeline, [NotNull] Action<CancellationToken> operation, [NotNull] Action<CancellationToken> fallback, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null, bool usePipelineForFallback = true)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                pipeline.Execute(operation, cancellationToken);
            }
            catch (Exception primaryException)
            {
                if (logExceptions && !(primaryException is OperationCanceledException))
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    if (usePipelineForFallback)
                        pipeline.Execute(fallback, cancellationToken);
                    else
                        fallback.Invoke(cancellationToken);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    return new DoubleException(primaryException, fallbackException);
                }

                return new DoubleException(primaryException, null);
            }

            return null;
        }

        /// <summary>
        /// Invokes <b>operation</b> safely, effectively <b>try { operation.Invoke() } catch { }</b>. If that fails, the same is attempted with <b>fallback</b>.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the result type.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        /// <example><b>await ExecuteWithFallbackSafe(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        [NotNull]
        public static SafeFallbackResult<TResult> ExecuteWithFallbackSafe<TResult>([NotNull] Func<CancellationToken, TResult> operation, [NotNull] Func<CancellationToken, TResult> fallback, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null) => new SafeFallbackResult<TResult>(ExecuteWithFallbackSafe(operation, fallback, default!, cancellationToken, logExceptions, logOptions));

        /// <summary>
        /// Invokes <b>operation</b> safely, similar to <b>try { operation.Invoke() } catch { }</b>. If that fails, the same is attempted with <b>fallback</b>.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the value specified by <b>errorResultValue</b>.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        /// <example><b>await ExecuteWithFallbackSafe(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>, "Error")</b></example>
        [NotNull]
        public static SafeFallbackResult<TResult, object> ExecuteWithFallbackSafe<TResult>([NotNull] Func<CancellationToken, TResult> operation, [NotNull] Func<CancellationToken, TResult> fallback, [NotNull] TResult errorResultValue, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return new SafeFallbackResult<TResult, object>(operation.Invoke(cancellationToken), null, null);
            }
            catch (Exception primaryException)
            {
                if (logExceptions && !(primaryException is OperationCanceledException))
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    return new SafeFallbackResult<TResult, object>(fallback.Invoke(cancellationToken), primaryException, null);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    return new SafeFallbackResult<TResult, object>(errorResultValue, primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Invokes <b>operation</b> safely, similar to <b>try { operation.Invoke() } catch { }</b>.<br/><br/>
        /// DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns <b>null</b> if the fallback was not needed, otherwise a <b>DoubleException</b> with the <b>fallback</b> and/or <b>operation</b> exception.</returns>
        /// <example><b>await ExecuteWithFallbackSafe(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        [CanBeNull]
        public static DoubleException ExecuteWithFallbackSafe([NotNull] Action<CancellationToken> operation, [NotNull] Action<CancellationToken> fallback, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                operation.Invoke(cancellationToken);
            }
            catch (Exception primaryException)
            {
                if (logExceptions && !(primaryException is OperationCanceledException))
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    fallback.Invoke(cancellationToken);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    return new DoubleException(primaryException, fallbackException);
                }

                return new DoubleException(primaryException, null);
            }

            return null;
        }

        #endregion

        #region Fallback Unsafe

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b>. If that fails, this executes <b>pipeline.Execute(fallback)</b>, or <b>fallback.Invoke()</b> if <b>usePipelineForFallback</b> is specified.
        /// </summary>
        /// <exception cref="DoubleException">This will always be the exception thrown if both <b>operation</b> and <b>fallback</b> fail, and contains the corresponding exceptions.</exception>
        /// <exception cref="OperationCanceledException">This will be the exception thrown if <b>cancellationToken</b> is cancelled between execution of <b>operation</b> and <b>fallback</b>.</exception>
        /// <example><b>await pipeline.ExecuteWithFallback(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        public static TResult ExecuteWithFallback<TResult>(this ResiliencePipeline<TResult> pipeline, [NotNull] Func<CancellationToken, TResult> operation, [NotNull] Func<CancellationToken, TResult> fallback, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null, bool usePipelineForFallback = true)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return pipeline.Execute(operation, cancellationToken);
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    if (usePipelineForFallback)
                        return pipeline.Execute(fallback, cancellationToken);
                    else
                        return fallback.Invoke(cancellationToken);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    throw new DoubleException(primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b>. If that fails, this executes <b>pipeline.Execute(fallback)</b>, or <b>fallback.Invoke()</b> if <b>usePipelineForFallback</b> is specified.
        /// </summary>
        /// <exception cref="DoubleException">This will always be the exception thrown if both <b>operation</b> and <b>fallback</b> fail, and contains the corresponding exceptions.</exception>
        /// <exception cref="OperationCanceledException">This will be the exception thrown if <b>cancellationToken</b> is cancelled between execution of <b>operation</b> and <b>fallback</b>.</exception>
        /// <example><b>await pipeline.ExecuteWithFallback(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        public static TResult ExecuteWithFallback<TResult>(this ResiliencePipeline pipeline, [NotNull] Func<CancellationToken, TResult> operation, [NotNull] Func<CancellationToken, TResult> fallback, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null, bool usePipelineForFallback = true)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return pipeline.Execute(operation, cancellationToken);
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    if (usePipelineForFallback)
                        return pipeline.Execute(fallback, cancellationToken);
                    else
                        return fallback.Invoke(cancellationToken);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    throw new DoubleException(primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Executes <b>pipeline.Execute(operation)</b>. If that fails, this executes <b>pipeline.Execute(fallback)</b>, or <b>fallback.Invoke()</b> if <b>usePipelineForFallback</b> is specified.
        /// </summary>
        /// <exception cref="DoubleException">This will always be the exception thrown if both <b>operation</b> and <b>fallback</b> fail, and contains the corresponding exceptions.</exception>
        /// <exception cref="OperationCanceledException">This will be the exception thrown if <b>cancellationToken</b> is cancelled between execution of <b>operation</b> and <b>fallback</b>.</exception>
        /// <example><b>await pipeline.ExecuteWithFallback(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        public static void ExecuteWithFallback(this ResiliencePipeline pipeline, [NotNull] Action<CancellationToken> operation, [NotNull] Action<CancellationToken> fallback, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null, bool usePipelineForFallback = true)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                pipeline.Execute(operation, cancellationToken);
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    if (usePipelineForFallback)
                        pipeline.Execute(fallback, cancellationToken);
                    else
                        fallback.Invoke(cancellationToken);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    throw new DoubleException(primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Invokes <b>operation</b>. If that fails, this invokes <b>fallback</b>.
        /// </summary>
        /// <exception cref="DoubleException">This will always be the exception thrown if both <b>operation</b> and <b>fallback</b> fail, and contains the corresponding exceptions.</exception>
        /// <exception cref="OperationCanceledException">This will be the exception thrown if <b>cancellationToken</b> is cancelled between execution of <b>operation</b> and <b>fallback</b>.</exception>
        /// <example><b>await ExecuteWithFallback(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        [NotNull]
        public static TResult ExecuteWithFallback<TResult>([NotNull] Func<CancellationToken, TResult> operation, [NotNull] Func<CancellationToken, TResult> fallback, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return operation.Invoke(cancellationToken);
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    return fallback.Invoke(cancellationToken);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    throw new DoubleException(primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Invokes <b>operation</b>. If that fails, this invokes <b>fallback</b>.
        /// </summary>
        /// <exception cref="DoubleException">This will always be the exception thrown if both <b>operation</b> and <b>fallback</b> fail, and contains the corresponding exceptions.</exception>
        /// <exception cref="OperationCanceledException">This will be the exception thrown if <b>cancellationToken</b> is cancelled between execution of <b>operation</b> and <b>fallback</b>.</exception>
        /// <example><b>await ExecuteWithFallback(() => </b><i>your code here...</i><b>, () => </b><i>your fallback code here...</i><b>)</b></example>
        public static void ExecuteWithFallback([NotNull] Action<CancellationToken> operation, [NotNull] Action<CancellationToken> fallback, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                operation.Invoke(cancellationToken);
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    fallback.Invoke(cancellationToken);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    throw new DoubleException(primaryException, fallbackException);
                }
            }
        }

        #endregion
        
        #endregion

        #region Async

        #region Safe

        /// <summary>
        /// Executes <b>pipeline.ExecuteAsync(operation)</b> safely.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the result type.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        /// <example><b>await pipeline.ExecuteSafeAsync(async token => </b><i>your async code here...</i><b>)</b></example>
        [ItemNotNull]
        public static async Task<SafeResult<TResult>> ExecuteSafeAsync<TResult>(this ResiliencePipeline<TResult> pipeline, [NotNull] Func<CancellationToken, ValueTask<TResult>> operation, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null) => new SafeResult<TResult>(await ExecuteSafeAsync(pipeline, operation, default!, cancellationToken, logExceptions, logOptions));

        /// <summary>
        /// Executes <b>pipeline.ExecuteAsync(operation)</b> safely.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the value specified by <b>errorResultValue</b>.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        /// <example><b>await pipeline.ExecuteSafeAsync(async token => </b><i>your async code here...</i><b>, "Error")</b></example>
        [ItemNotNull]
        public static async Task<SafeResult<TResult, object>> ExecuteSafeAsync<TResult>(this ResiliencePipeline<TResult> pipeline, [NotNull] Func<CancellationToken, ValueTask<TResult>> operation, [NotNull] TResult errorResultValue, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return new SafeResult<TResult, object>(await pipeline.ExecuteAsync(operation, cancellationToken), null);
            }
            catch (Exception e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(e, logOptions);
                return new SafeResult<TResult, object>(errorResultValue, e);
            }
        }

        /// <summary>
        /// Executes <b>pipeline.ExecuteAsync(operation)</b> safely.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the result type.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        /// <example><b>await pipeline.ExecuteSafeAsync(async token => </b><i>your async code here...</i><b>)</b></example>
        [ItemNotNull]
        public static async Task<SafeResult<TResult>> ExecuteSafeAsync<TResult>(this ResiliencePipeline pipeline, [NotNull] Func<CancellationToken, ValueTask<TResult>> operation, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null) => new SafeResult<TResult>(await ExecuteSafeAsync(pipeline, operation, default!, cancellationToken, logExceptions, logOptions));

        /// <summary>
        /// Executes <b>pipeline.ExecuteAsync(operation)</b> safely.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the result type.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        /// <example><b>await pipeline.ExecuteSafeAsync(async token => </b><i>your async code here...</i><b>, "Error")</b></example>
        [ItemNotNull]
        public static async Task<SafeResult<TResult, object>> ExecuteSafeAsync<TResult>(this ResiliencePipeline pipeline, [NotNull] Func<CancellationToken, ValueTask<TResult>> operation, [NotNull] TResult errorResultValue, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return new SafeResult<TResult, object>(await pipeline.ExecuteAsync(operation, cancellationToken), null);
            }
            catch (Exception e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(e, logOptions);
                return new SafeResult<TResult, object>(errorResultValue, e);
            }
        }

        /// <summary>
        /// Executes <b>pipeline.ExecuteAsync(operation)</b> safely.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>The exception thrown, or null if successful.</returns>
        /// <example><b>await pipeline.ExecuteSafeAsync(async token => </b><i>your async code here...</i><b>)</b></example>
        [ItemCanBeNull]
        public static async Task<Exception> ExecuteSafeAsync(this ResiliencePipeline pipeline, [NotNull] Func<CancellationToken, ValueTask> operation, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                await pipeline.ExecuteAsync(operation, cancellationToken);
            }
            catch (Exception e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(e, logOptions);
                return e;
            }

            return null;
        }

        /// <summary>
        /// Invokes <b>operation</b> safely and asynchronously, similar to <b>try { await operation.Invoke() } catch { }</b>.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the result type.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        /// <example><b>await ExecuteSafeAsync(async token => </b><i>your async code here...</i><b>)</b></example>
        [ItemNotNull]
        public static async Task<SafeResult<TResult>> ExecuteSafeAsync<TResult>([NotNull] Func<CancellationToken, Task<TResult>> operation, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null) => new SafeResult<TResult>(await ExecuteSafeAsync(operation, default!, cancellationToken, logExceptions, logOptions));

        /// <summary>
        /// Executes <b>operation</b> safely and asynchronously, similar to <b>try { await operation.Invoke() } catch { }</b>.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the value specified by <b>errorResultValue</b>.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        /// <example><b>await ExecuteSafeAsync(async token => </b><i>your async code here...</i><b>, "Error")</b></example>
        [ItemNotNull]
        public static async Task<SafeResult<TResult, object>> ExecuteSafeAsync<TResult>([NotNull] Func<CancellationToken, Task<TResult>> operation, [NotNull] TResult errorResultValue, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return new SafeResult<TResult, object>(await operation.Invoke(cancellationToken), null);
            }
            catch (Exception e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(e, logOptions);
                return new SafeResult<TResult, object>(errorResultValue, e);
            }
        }

        /// <summary>
        /// Invokes <b>operation</b> safely and asynchronously, similar to <b>try { await operation.Invoke() } catch { }</b>.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns <b>null</b> upon success, otherwise the exception thrown.</returns>
        /// <example><b>await ExecuteSafeAsync(async token => </b><i>your async code here...</i><b>)</b></example>
        [ItemCanBeNull]
        public static async Task<Exception> ExecuteSafeAsync([NotNull] Func<CancellationToken, Task> operation, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                await operation.Invoke(cancellationToken);
            }
            catch (Exception e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(e, logOptions);
                return e;
            }

            return null;
        }

        #endregion

        #region Fallback Safe

        /// <summary>
        /// Executes <b>pipeline.ExecuteAsync(operation, cancellationToken)</b> safely. If that fails, this executes <b>pipeline.ExecuteAsync(fallback, cancellationToken)</b> safely, or <b>fallback.Invoke(cancellationToken)</b> if <b>usePipelineForFallback</b> is specified.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// <param name="usePipelineForFallback">Specifies to run <b>fallback</b> without the supplied pipeline.</param>
        /// </summary>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the return type.<br/><b>PrimaryException</b>: Set to null if <b>operation</b> was successful, otherwise the exception from the operation.<br/><b>FallbackException</b>: Set to null if the <b>fallback</b> was successful or was not called, otherwise the exception from the fallback.</returns>
        /// <example><b>await pipeline.ExecuteWithFallbackSafeAsync(async token => </b><i>your async code here...</i><b>, async token => </b><i>your async fallback code here...</i><b>)</b></example>
        [ItemNotNull]
        public static async Task<SafeFallbackResult<TResult>> ExecuteWithFallbackSafeAsync<TResult>(this ResiliencePipeline<TResult> pipeline, [NotNull] Func<CancellationToken, ValueTask<TResult>> operation, [NotNull] Func<CancellationToken, ValueTask<TResult>> fallback, bool usePipelineForFallback = true, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null) => new SafeFallbackResult<TResult>(await ExecuteWithFallbackSafeAsync(pipeline, operation, fallback, default!, logExceptions, logOptions, usePipelineForFallback, cancellationToken));

        /// <summary>
        /// Executes <b>pipeline.ExecuteAsync(operation, cancellationToken)</b> safely. If that fails, this executes <b>pipeline.ExecuteAsync(fallback, cancellationToken)</b> safely, or <b>fallback.Invoke(cancellationToken)</b> if <b>usePipelineForFallback</b> is specified.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="usePipelineForFallback">Specifies to run <b>fallback</b> without the supplied pipeline.</param>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation or fallback.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the value specified by <b>errorResultValue</b>.<br/><b>PrimaryException</b>: Set to null if <b>operation</b> was successful, otherwise the exception from the operation.<br/><b>FallbackException</b>: Set to null if the <b>fallback</b> was successful or was not called, otherwise the exception from the fallback.</returns>
        /// <example><b>await pipeline.ExecuteWithFallbackSafeAsync(async token => </b><i>your async code here...</i><b>, async token => </b><i>your async fallback code here...</i><b>, "Error")</b></example>
        [ItemNotNull]
        public static async Task<SafeFallbackResult<TResult, object>> ExecuteWithFallbackSafeAsync<TResult>(this ResiliencePipeline<TResult> pipeline, [NotNull] Func<CancellationToken, ValueTask<TResult>> operation, [NotNull] Func<CancellationToken, ValueTask<TResult>> fallback, [NotNull] TResult errorResultValue, bool logExceptions = false, Log.LogOptions logOptions = null, bool usePipelineForFallback = true, CancellationToken cancellationToken = default)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return new SafeFallbackResult<TResult, object>(await pipeline.ExecuteAsync(operation, cancellationToken), null, null);
            }
            catch (Exception primaryException)
            {
                if (logExceptions && !(primaryException is OperationCanceledException))
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (usePipelineForFallback)
                        return new SafeFallbackResult<TResult, object>(await pipeline.ExecuteAsync(fallback, cancellationToken), primaryException, null);
                    else
                        return new SafeFallbackResult<TResult, object>(await fallback.Invoke(cancellationToken), primaryException, null);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    return new SafeFallbackResult<TResult, object>(errorResultValue, primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Executes <b>pipeline.ExecuteAsync(operation, cancellationToken)</b> safely. If that fails, this executes <b>pipeline.ExecuteAsync(fallback, cancellationToken)</b> safely, or <b>fallback.Invoke(cancellationToken)</b> if <b>usePipelineForFallback</b> is specified.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="usePipelineForFallback">Specifies to run <b>fallback</b> without the supplied pipeline.</param>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the return type.<br/><b>PrimaryException</b>: Set to null if <b>operation</b> was successful, otherwise the exception from the operation.<br/><b>FallbackException</b>: Set to null if the <b>fallback</b> was successful or was not called, otherwise the exception from the fallback.</returns>
        /// <example><b>await pipeline.ExecuteWithFallbackSafeAsync(async token => </b><i>your async code here...</i><b>, async token => </b><i>your async fallback code here...</i><b>)</b></example>
        [ItemNotNull]
        public static async Task<SafeFallbackResult<TResult>> ExecuteWithFallbackSafeAsync<TResult>(this ResiliencePipeline pipeline, [NotNull] Func<CancellationToken, ValueTask<TResult>> operation, [NotNull] Func<CancellationToken, ValueTask<TResult>> fallback, bool usePipelineForFallback = true, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null) => new SafeFallbackResult<TResult>(await ExecuteWithFallbackSafeAsync(pipeline, operation, fallback, default!, usePipelineForFallback, cancellationToken));

        /// <summary>
        /// Executes <b>await pipeline.ExecuteAsync(operation, cancellationToken)</b> safely. If that fails, this executes <b>await pipeline.ExecuteAsync(fallback, cancellationToken)</b> safely, or <b>await fallback.Invoke(cancellationToken)</b> if <b>usePipelineForFallback</b> is specified.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="usePipelineForFallback">Specifies to run <b>fallback</b> without the supplied pipeline.</param>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the value specified by <b>errorResultValue</b>.<br/><b>PrimaryException</b>: Set to null if <b>operation</b> was successful, otherwise the exception from the operation.<br/><b>FallbackException</b>: Set to null if the <b>fallback</b> was successful or was not called, otherwise the exception from the fallback.</returns>
        /// <example><b>await pipeline.ExecuteWithFallbackSafeAsync(async token => </b><i>your async code here...</i><b>, async token => </b><i>your async fallback code here...</i><b>, "Error")</b></example>
        [ItemNotNull]
        public static async Task<SafeFallbackResult<TResult, object>> ExecuteWithFallbackSafeAsync<TResult>(this ResiliencePipeline pipeline, [NotNull] Func<CancellationToken, ValueTask<TResult>> operation, [NotNull] Func<CancellationToken, ValueTask<TResult>> fallback, [NotNull] TResult errorResultValue, bool usePipelineForFallback = true, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return new SafeFallbackResult<TResult, object>(await pipeline.ExecuteAsync(operation, cancellationToken), null, null);
            }
            catch (Exception primaryException)
            {
                if (logExceptions && !(primaryException is OperationCanceledException))
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (usePipelineForFallback)
                        return new SafeFallbackResult<TResult, object>(await pipeline.ExecuteAsync(fallback, cancellationToken), primaryException, null);
                    else
                        return new SafeFallbackResult<TResult, object>(await fallback.Invoke(cancellationToken), primaryException, null);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    return new SafeFallbackResult<TResult, object>(errorResultValue, primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Executes <b>await pipeline.ExecuteAsync(operation, cancellationToken)</b> safely. If that fails, this executes <b>await pipeline.ExecuteAsync(fallback, cancellationToken)</b> safely, or <b>await fallback.Invoke(cancellationToken)</b> if <b>usePipelineForFallback</b> is specified.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="usePipelineForFallback">Specifies to run <b>fallback</b> without the supplied pipeline.</param>
        /// <returns>Returns a <b>DoubleException</b>:<br/><b>PrimaryException</b>: Set to null if <b>operation</b> was successful, otherwise the exception from the operation.<br/><b>FallbackException</b>: Set to null if the <b>fallback</b> was successful or was not called, otherwise the exception from the fallback.</returns>
        /// <example><b>await pipeline.ExecuteWithFallbackSafeAsync(async token => </b><i>your async code here...</i><b>, async token => </b><i>your async fallback code here...</i><b>)</b></example>
        [ItemCanBeNull]
        public static async Task<DoubleException> ExecuteWithFallbackSafeAsync(this ResiliencePipeline pipeline, [NotNull] Func<CancellationToken, ValueTask> operation, [NotNull] Func<CancellationToken, ValueTask> fallback, bool usePipelineForFallback = true, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                await pipeline.ExecuteAsync(operation, cancellationToken);
            }
            catch (Exception primaryException)
            {
                if (logExceptions && !(primaryException is OperationCanceledException))
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (usePipelineForFallback)
                        await pipeline.ExecuteAsync(fallback, cancellationToken);
                    else
                        await fallback.Invoke(cancellationToken);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    return new DoubleException(primaryException, fallbackException);
                }

                return new DoubleException(primaryException, null);
            }

            return null;
        }

        /// <summary>
        /// Executes <b>pipeline.ExecuteAsync(operation, cancellationToken)</b> safely. If that fails, this executes <b>pipeline.ExecuteAsync(fallback, cancellationToken)</b> safely, or <b>fallback.Invoke(cancellationToken)</b> if usePipelineForFallback is specified.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the default value for the result type.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        /// <example><b>await ExecuteWithFallbackSafeAsync(async token => </b><i>your async code here...</i><b>, async token => </b><i>your async fallback code here...</i><b>)</b></example>
        [ItemNotNull]
        public static async Task<SafeFallbackResult<TResult>> ExecuteWithFallbackSafeAsync<TResult>([NotNull] Func<CancellationToken, Task<TResult>> operation, [NotNull] Func<CancellationToken, Task<TResult>> fallback, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null) => new SafeFallbackResult<TResult>(await ExecuteWithFallbackSafeAsync(operation, fallback, default!, cancellationToken, logExceptions, logOptions));

        /// <summary>
        /// Executes <b>pipeline.ExecuteAsync(operation, cancellationToken)</b> safely. If that fails, this executes <b>pipeline.ExecuteAsync(fallback, cancellationToken)</b> safely, or <b>fallback.Invoke(cancellationToken)</b> if usePipelineForFallback is specified.
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <param name="errorResultValue">Result value when no value could be retrieved from the operation.<br/>This should not be null, instead omit this parameter to return a null (default) result value upon error.</param>
        /// <returns>Returns a <b>SafeFallbackResult</b> structure:<br/><b>Value</b>: Set to the result upon success, otherwise the value specified by <b>errorResultValue</b>.<br/><b>Exception</b>: Set to null upon success, otherwise the exception thrown.</returns>
        /// <example><b>await ExecuteWithFallbackSafeAsync(async token => </b><i>your async code here...</i><b>, async token => </b><i>your async fallback code here...</i><b>, "Error")</b></example>
        [ItemNotNull]
        public static async Task<SafeFallbackResult<TResult, object>> ExecuteWithFallbackSafeAsync<TResult>([NotNull] Func<CancellationToken, Task<TResult>> operation, [NotNull] Func<CancellationToken, Task<TResult>> fallback, [NotNull] TResult errorResultValue, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return new SafeFallbackResult<TResult, object>(await operation.Invoke(cancellationToken), null, null);
            }
            catch (Exception primaryException)
            {
                if (logExceptions && !(primaryException is OperationCanceledException))
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    return new SafeFallbackResult<TResult, object>(await fallback.Invoke(cancellationToken), primaryException, null);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    return new SafeFallbackResult<TResult, object>(errorResultValue, primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Executes code safely and asynchronously, effectively <b>try { await operation.Invoke(cancellationToken) } catch { }</b>.<br/><br/>
        /// <br/><br/>DOES NOT THROW EXCEPTION UPON FAILURE.
        /// </summary>
        /// <returns>Returns <b>null</b> if the fallback was not needed, otherwise a <b>DoubleException</b> with the <b>fallback</b> and/or <b>operation</b> exception.</returns>
        /// <example><b>await ExecuteWithFallbackSafeAsync(async token => </b><i>your async code here...</i><b>, async token => </b><i>your async fallback code here...</i><b>)</b></example>
        [ItemCanBeNull]
        public static async Task<DoubleException> ExecuteWithFallbackSafeAsync([NotNull] Func<CancellationToken, Task> operation, [NotNull] Func<CancellationToken, Task> fallback, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                await operation.Invoke(cancellationToken);
            }
            catch (Exception primaryException)
            {
                if (logExceptions && !(primaryException is OperationCanceledException))
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    await fallback.Invoke(cancellationToken);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    return new DoubleException(primaryException, fallbackException);
                }

                return new DoubleException(primaryException, null);
            }

            return null;
        }

        #endregion Fallback Safe

        #region Fallback Unsafe

        /// <summary>
        /// Executes <b>pipeline.ExecuteAsync(operation)</b>. If that fails, this executes <b>pipeline.ExecuteAsync(fallback)</b> or <b>fallback.Invoke()</b> if usePipelineForFallback is specified.
        /// </summary>
        /// <exception cref="DoubleException">This will always be the exception thrown if both <b>operation</b> and <b>fallback</b> fail, and contains the corresponding exceptions.</exception>
        /// <exception cref="OperationCanceledException">This will be the exception thrown if <b>cancellationToken</b> is cancelled between execution of <b>operation</b> and <b>fallback</b>.</exception>
        /// <example><b>await pipeline.ExecuteWithFallbackAsync(async token => </b><i>your async code here...</i><b>, async token => </b><i>your async fallback code here...</i><b>)</b></example>
        public static async Task<TResult> ExecuteWithFallbackAsync<TResult>(this ResiliencePipeline pipeline, [NotNull] Func<CancellationToken, ValueTask<TResult>> operation, [NotNull] Func<CancellationToken, ValueTask<TResult>> fallback, bool usePipelineForFallback = true, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return await pipeline.ExecuteAsync(operation, cancellationToken);
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    if (usePipelineForFallback)
                        return await pipeline.ExecuteAsync(fallback, cancellationToken);
                    else
                        return await fallback.Invoke(cancellationToken);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    throw new DoubleException(primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Executes <b>pipeline.ExecuteAsync(operation)</b>. If that fails, this executes <b>pipeline.ExecuteAsync(fallback)</b> or <b>fallback.Invoke()</b> if usePipelineForFallback is specified.
        /// </summary>
        /// <exception cref="DoubleException">This will always be the exception thrown if both <b>operation</b> and <b>fallback</b> fail, and contains the corresponding exceptions.</exception>
        /// <exception cref="OperationCanceledException">This will be the exception thrown if <b>cancellationToken</b> is cancelled between execution of <b>operation</b> and <b>fallback</b>.</exception>
        /// <example><b>await pipeline.ExecuteWithFallbackAsync(async token => </b><i>your async code here...</i><b>, async token => </b><i>your async fallback code here...</i><b>)</b></example>
        public static async Task ExecuteWithFallbackAsync(this ResiliencePipeline pipeline, [NotNull] Func<CancellationToken, ValueTask> operation, [NotNull] Func<CancellationToken, ValueTask> fallback, bool usePipelineForFallback = true, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                await pipeline.ExecuteAsync(operation, cancellationToken);
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    if (usePipelineForFallback)
                        await pipeline.ExecuteAsync(fallback, cancellationToken);
                    else
                        await fallback.Invoke(cancellationToken);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    throw new DoubleException<object>(primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Executes <b>pipeline.ExecuteAsync(operation)</b>. If that fails, this executes <b>pipeline.ExecuteAsync(fallback)</b> or <b>fallback.Invoke()</b> if usePipelineForFallback is specified.
        /// </summary>
        /// <exception cref="DoubleException">This will always be the exception thrown if both <b>operation</b> and <b>fallback</b> fail, and contains the corresponding exceptions.</exception>
        /// <exception cref="OperationCanceledException">This will be the exception thrown if <b>cancellationToken</b> is cancelled between execution of <b>operation</b> and <b>fallback</b>.</exception>
        /// <example><b>await ExecuteWithFallbackAsync(async token => </b><i>your async code here...</i><b>, async token => </b><i>your async fallback code here...</i><b>)</b></example>
        public static async Task<TResult> ExecuteWithFallbackAsync<TResult>([NotNull] Func<CancellationToken, Task<TResult>> operation, [NotNull] Func<CancellationToken, Task<TResult>> fallback, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                return await operation.Invoke(cancellationToken);
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    return await fallback.Invoke(cancellationToken);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    throw new DoubleException<object>(primaryException, fallbackException);
                }
            }
        }

        /// <summary>
        /// Executes <b>pipeline.ExecuteAsync(operation)</b>. If that fails, this executes <b>pipeline.ExecuteAsync(fallback)</b> or <b>fallback.Invoke()</b> if usePipelineForFallback is specified.
        /// </summary>
        /// <exception cref="DoubleException">This will always be the exception thrown if both <b>operation</b> and <b>fallback</b> fail, and contains the corresponding exceptions.</exception>
        /// <exception cref="OperationCanceledException">This will be the exception thrown if <b>cancellationToken</b> is cancelled between execution of <b>operation</b> and <b>fallback</b>.</exception>
        /// <example><b>await ExecuteWithFallbackAsync(async token => </b><i>your async code here...</i><b>, async token => </b><i>your async fallback code here...</i><b>)</b></example>
        public static async Task ExecuteWithFallbackAsync([NotNull] Func<CancellationToken, Task> operation, [NotNull] Func<CancellationToken, Task> fallback, CancellationToken cancellationToken = default, bool logExceptions = false, Log.LogOptions logOptions = null)
        {
            ThrowIfNull(operation, nameof(operation));
            ThrowIfNull(fallback, nameof(fallback));

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                await operation.Invoke(cancellationToken);
            }
            catch (Exception primaryException)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(primaryException, logOptions);
                
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    await fallback.Invoke(cancellationToken);
                }
                catch (Exception fallbackException)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(fallbackException, "Fallback", logOptions);
                    throw new DoubleException<object>(primaryException, fallbackException);
                }
            }
        }

        #endregion Fallback Unsafe

        #endregion

        #endregion

        private static void ThrowIfNull<TArgument>(TArgument argument, string name)
        {
            Task.Run(() => { });
            if (argument == null)
                throw new ArgumentNullException(name);
        }
    }

    public class SafeTask<TResult>
    {
        public readonly Task<Wrap.SafeResult<TResult>> Task;
        public SafeTask(Func<TResult> function, bool logExceptions, Log.LogOptions logOptions = null) => Task = new Task<Wrap.SafeResult<TResult>>(() => Wrap.ExecuteSafe(function, logExceptions, logOptions));
        public void Start() => Task.Start();
    }
    public class SafeTask
    {
        [ItemCanBeNull] public readonly Task<Exception> Task;
        public SafeTask(Action action, bool logExceptions, Log.LogOptions logOptions = null) => Task = new Task<Exception>(() => Wrap.ExecuteSafe(action, logExceptions, logOptions));
        public void Start() => Task.Start();
        
        public static Task<Exception> Run(Action action, bool logExceptions = false, Log.LogOptions logOptions = null) => System.Threading.Tasks.Task.Run(() => Wrap.ExecuteSafe(action, logExceptions, logOptions), CancellationToken.None);
        public static Task<Exception> Run(Action action, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null) => System.Threading.Tasks.Task.Run(() => Wrap.ExecuteSafe(action, logExceptions, logOptions), cancellationToken);
        public static Task<Wrap.SafeResult<TResult>> Run<TResult>(Func<TResult> function, bool logExceptions = false, Log.LogOptions logOptions = null) => System.Threading.Tasks.Task.Run(() => Wrap.ExecuteSafe(function, logExceptions, logOptions), CancellationToken.None);
        public static Task<Wrap.SafeResult<TResult>> Run<TResult>(Func<TResult> function, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null) => System.Threading.Tasks.Task.Run(() => Wrap.ExecuteSafe(function, logExceptions, logOptions), cancellationToken);

        public static Task<Exception> Run(Func<Task> function, bool logExceptions = false, Log.LogOptions logOptions = null) => System.Threading.Tasks.Task.Run(() => Wrap.ExecuteSafeAsync(token => function.Invoke(), CancellationToken.None, logExceptions, logOptions), CancellationToken.None);
        public static Task<Exception> Run(Func<Task> function, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null) => System.Threading.Tasks.Task.Run(() => Wrap.ExecuteSafeAsync(token => function.Invoke(), cancellationToken, logExceptions, logOptions), cancellationToken);
        public static Task<Wrap.SafeResult<TResult>> Run<TResult>(Func<Task<TResult>> function, bool logExceptions = false, Log.LogOptions logOptions = null) => System.Threading.Tasks.Task.Run(() => Wrap.ExecuteSafeAsync( token => function.Invoke(), CancellationToken.None, logExceptions, logOptions));
        public static Task<Wrap.SafeResult<TResult>> Run<TResult>(Func<Task<TResult>> function, CancellationToken cancellationToken, bool logExceptions = false, Log.LogOptions logOptions = null) => System.Threading.Tasks.Task.Run(() => Wrap.ExecuteSafeAsync(token => function.Invoke(), cancellationToken, logExceptions, logOptions), cancellationToken);
    }
}