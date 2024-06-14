using System;

namespace Interprocess
{
    public enum Level
    {
        Any,
        Disposable,
        
        // Add/remove level here
        User,
        Administrator,
        TrustedInstaller,
    }

    public enum TargetLevel
    {
        Auto,
        Disposable,
        
        // And add/remove level here
        User,
        Administrator,
        TrustedInstaller,
    }

    public partial class InterLink
    {
        public enum InternalLevel
        {
            Uninitialized,
            Disposable,
            
            // And add/remove level here
            User,
            Administrator,
            TrustedInstaller,
        }
        

        public static InternalLevel ToInternalLevel(this Level level)
        {
            return level switch
            {
                // And add/remove conversion line here
                Level.User => InternalLevel.User,
                Level.Administrator => InternalLevel.Administrator,
                Level.TrustedInstaller => InternalLevel.TrustedInstaller,
                
                Level.Disposable => InternalLevel.Disposable,
                Level.Any => throw new InvalidOperationException("Invalid conversion of Level.Any to InternalLevel."),
                _ => throw new InvalidOperationException()
            };
        }

        public static InternalLevel ToInternalLevel(this TargetLevel level)
        {
            return level switch
            {
                // And add/remove conversion line here
                TargetLevel.User => InternalLevel.User,
                TargetLevel.Administrator => InternalLevel.Administrator,
                TargetLevel.TrustedInstaller => InternalLevel.TrustedInstaller,
                
                TargetLevel.Disposable => InternalLevel.Disposable,
                TargetLevel.Auto => throw new InvalidOperationException("Invalid conversion of TargetLevel.Auto to InternalLevel."),
                _ => throw new InvalidOperationException()
            };
        }

        public static Level ToLevel(this TargetLevel level)
        {
            return level switch
            {
                // And add/remove conversion line here
                TargetLevel.User => Level.User,
                TargetLevel.Administrator => Level.Administrator,
                TargetLevel.TrustedInstaller => Level.TrustedInstaller,
                
                TargetLevel.Disposable => Level.Disposable,
                TargetLevel.Auto => throw new InvalidOperationException("Invalid conversion of TargetLevel.Auto to Level."),
                _ => throw new InvalidOperationException()
            };
        }

        public static Level ToLevel(this InternalLevel level)
        {
            return level switch
            {
                // And add/remove conversion line here
                InternalLevel.User => Level.User,
                InternalLevel.Administrator => Level.Administrator,
                InternalLevel.TrustedInstaller => Level.TrustedInstaller,
                
                InternalLevel.Disposable => Level.Disposable,
                InternalLevel.Uninitialized => throw new InvalidOperationException("Invalid conversion of InternalLevel.Uninitialized to Level."),
                _ => throw new InvalidOperationException()
            };
        }
        
        public static TargetLevel ToTargetLevel(this InternalLevel level)
        {
            return level switch
            {
                // And add/remove conversion line here
                InternalLevel.User => TargetLevel.User,
                InternalLevel.Administrator => TargetLevel.Administrator,
                InternalLevel.TrustedInstaller => TargetLevel.TrustedInstaller,
                
                InternalLevel.Disposable => TargetLevel.Disposable,
                InternalLevel.Uninitialized => throw new InvalidOperationException("Invalid conversion of InternalLevel.Uninitialized to TargetLevel."),
                _ => throw new InvalidOperationException()
            };
        }
        public static TargetLevel ToTargetLevel(this Level level)
        {
            return level switch
            {
                // And add/remove conversion line here
                Level.User => TargetLevel.User,
                Level.Administrator => TargetLevel.Administrator,
                Level.TrustedInstaller => TargetLevel.TrustedInstaller,
                
                Level.Disposable => TargetLevel.Disposable,
                Level.Any => throw new InvalidOperationException("Invalid conversion of Level.Any to TargetLevel."),
                _ => throw new InvalidOperationException()
            };
        }
    }
}